/* SPDX-License-Identifier: Apache-2.0 */
/*
 * YukiZygisk - Userspace root-policy fallback.
 *
 * License: Apache-2.0
 *
 * Author: Anatdx
 */

#include "root_policy.hpp"

#include <dirent.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <map>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace yzpolicy {
namespace {

constexpr char kKsuAllowlist[] = "/data/adb/ksu/.allowlist";
constexpr char kApatchConfig[] = "/data/adb/ap/package_config";
constexpr uint32_t kKsuAllowlistMagic = 0x7f4b5355U;
constexpr uint32_t kKsuDefaultProfileUid = 9999U;
constexpr uint32_t kKsuWebViewZygoteUid = 1053U;
constexpr size_t kKsuLegacyProfileSize = 776;
constexpr size_t kKsuV4ProfileSize = 784;
constexpr size_t kKsuUidOffset = 260;
constexpr size_t kKsuKeyOffset = 4;
constexpr size_t kKsuKeySize = 256;
constexpr size_t kMaxPolicyFile = 16 * 1024 * 1024;

constexpr int kKsuOption = static_cast<int>(0xdeadbeefU);
constexpr int kKsuInstallMagic2 = static_cast<int>(0xcafebabeU);
constexpr unsigned long kKsuIoctlGetInfo = 0x80004b02UL;
constexpr unsigned long kKsuIoctlUidShouldUmount = 0xc0004b09UL;
constexpr unsigned long kKsuIoctlGetManagerUid = 0x80004b0aUL;
constexpr unsigned long kKsuCmdGetVersion = 2;
constexpr unsigned long kKsuCmdUidShouldUmount = 13;
constexpr unsigned long kKsuCmdGetManagerUid = 16;

static_assert(sizeof(yz_policy_cache_header) == 32);
static_assert(sizeof(yz_policy_cache_entry) == 8);

#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif
#ifndef MFD_ALLOW_SEALING
#define MFD_ALLOW_SEALING 0x0002U
#endif
#ifndef F_ADD_SEALS
#define F_ADD_SEALS 1033
#endif
#ifndef F_SEAL_SEAL
#define F_SEAL_SEAL 0x0001
#endif
#ifndef F_SEAL_SHRINK
#define F_SEAL_SHRINK 0x0002
#endif
#ifndef F_SEAL_GROW
#define F_SEAL_GROW 0x0004
#endif
#ifndef F_SEAL_WRITE
#define F_SEAL_WRITE 0x0008
#endif

void log_message(const char *fmt, ...) {
  static int kmsg = open("/dev/kmsg", O_WRONLY | O_CLOEXEC);
  if (kmsg < 0)
    return;

  char buf[320];
  int n = snprintf(buf, sizeof(buf), "<6>zygiskd: policy fallback: ");
  va_list ap;
  va_start(ap, fmt);
  int m = vsnprintf(buf + n, sizeof(buf) - static_cast<size_t>(n), fmt, ap);
  va_end(ap);
  if (m < 0)
    return;
  size_t len = static_cast<size_t>(n) + static_cast<size_t>(m);
  if (len >= sizeof(buf))
    len = sizeof(buf) - 1;
  (void)write(kmsg, buf, len);
}

struct SourceStamp {
  dev_t dev = 0;
  ino_t ino = 0;
  off_t size = 0;
  time_t sec = 0;
  long nsec = 0;
  bool valid = false;
};

bool read_stamp(const char *path, SourceStamp *out) {
  struct stat st {};
  if (stat(path, &st) != 0)
    return false;
  out->dev = st.st_dev;
  out->ino = st.st_ino;
  out->size = st.st_size;
#if defined(__APPLE__)
  out->sec = st.st_mtimespec.tv_sec;
  out->nsec = st.st_mtimespec.tv_nsec;
#else
  out->sec = st.st_mtim.tv_sec;
  out->nsec = st.st_mtim.tv_nsec;
#endif
  out->valid = true;
  return true;
}

bool same_stamp(const SourceStamp &a, const SourceStamp &b) {
  return a.valid && b.valid && a.dev == b.dev && a.ino == b.ino &&
         a.size == b.size && a.sec == b.sec && a.nsec == b.nsec;
}

bool read_all(const char *path, std::vector<uint8_t> *out) {
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0)
    return false;
  struct stat st {};
  if (fstat(fd, &st) != 0 || st.st_size < 0 ||
      static_cast<uint64_t>(st.st_size) > kMaxPolicyFile) {
    close(fd);
    return false;
  }
  out->assign(static_cast<size_t>(st.st_size), 0);
  size_t done = 0;
  while (done < out->size()) {
    ssize_t n = read(fd, out->data() + done, out->size() - done);
    if (n < 0 && errno == EINTR)
      continue;
    if (n <= 0) {
      close(fd);
      return false;
    }
    done += static_cast<size_t>(n);
  }
  close(fd);
  return true;
}

bool write_all(int fd, const void *data, size_t size) {
  const auto *p = static_cast<const uint8_t *>(data);
  size_t done = 0;
  while (done < size) {
    ssize_t n = write(fd, p + done, size - done);
    if (n < 0 && errno == EINTR)
      continue;
    if (n <= 0)
      return false;
    done += static_cast<size_t>(n);
  }
  return true;
}

bool parse_u32(const std::string &text, uint32_t *value) {
  if (text.empty())
    return false;
  errno = 0;
  char *end = nullptr;
  unsigned long long parsed = strtoull(text.c_str(), &end, 10);
  if (errno != 0 || end == text.c_str() || *end != '\0' ||
      parsed > UINT32_MAX)
    return false;
  *value = static_cast<uint32_t>(parsed);
  return true;
}

std::vector<std::string> split_csv(const std::string &line) {
  std::vector<std::string> fields;
  std::string field;
  bool quoted = false;
  for (size_t i = 0; i < line.size(); ++i) {
    char c = line[i];
    if (c == '"') {
      if (quoted && i + 1 < line.size() && line[i + 1] == '"') {
        field.push_back('"');
        ++i;
      } else {
        quoted = !quoted;
      }
    } else if (c == ',' && !quoted) {
      fields.push_back(std::move(field));
      field.clear();
    } else {
      field.push_back(c);
    }
  }
  fields.push_back(std::move(field));
  return fields;
}

class KsuClient {
public:
  bool initialize() {
    if (method_ != Method::None)
      return true;

    int fd = scan_driver_fd();
    bool owns_fd = false;
    if (fd < 0) {
      fd = -1;
      (void)syscall(SYS_reboot, kKsuOption, kKsuInstallMagic2, 0, &fd);
      owns_fd = fd >= 0;
    }
    if (fd >= 0) {
      KsuGetInfoCmd info {};
      if (ioctl(fd, kKsuIoctlGetInfo, &info) == 0 && info.version != 0) {
        fd_ = fd;
        method_ = Method::Ioctl;
        return true;
      }
      if (owns_fd)
        close(fd);
    }

    int version = 0;
    int result = 0;
    (void)prctl(kKsuOption, kKsuCmdGetVersion, &version, 0, &result);
    if (version > 0) {
      method_ = Method::Prctl;
      return true;
    }
    return false;
  }

  bool query(uint32_t uid, bool *should_umount) {
    if (!initialize())
      return false;
    if (method_ == Method::Ioctl) {
      KsuUidShouldUmountCmd cmd {uid, 0};
      if (ioctl(fd_, kKsuIoctlUidShouldUmount, &cmd) != 0)
        return false;
      *should_umount = cmd.should_umount != 0;
      return true;
    }

    bool decision = false;
    uint32_t result = 0;
    (void)prctl(kKsuOption, kKsuCmdUidShouldUmount, uid, &decision,
                &result);
    if (result != static_cast<uint32_t>(kKsuOption))
      return false;
    *should_umount = decision;
    return true;
  }

  bool manager_appid(uint32_t *appid) {
    if (!initialize())
      return false;
    uint32_t uid = 0;
    if (method_ == Method::Ioctl) {
      KsuGetManagerUidCmd cmd {};
      if (ioctl(fd_, kKsuIoctlGetManagerUid, &cmd) == 0) {
        *appid = cmd.uid % 100000U;
        return true;
      }
    } else {
      uint32_t result = 0;
      (void)prctl(kKsuOption, kKsuCmdGetManagerUid, &uid, 0, &result);
      if (result == static_cast<uint32_t>(kKsuOption)) {
        *appid = uid % 100000U;
        return true;
      }
    }

    static const char *const paths[] = {
        "/data/user_de/0/me.weishu.kernelsu",
        "/data/user_de/0/com.rifsxd.ksunext",
        "/data/user_de/0/com.anatdx.yukisu",
    };
    for (const char *path : paths) {
      struct stat st {};
      if (stat(path, &st) == 0) {
        *appid = static_cast<uint32_t>(st.st_uid) % 100000U;
        return true;
      }
    }
    return false;
  }

private:
  enum class Method { None, Ioctl, Prctl };
  struct KsuGetInfoCmd {
    uint32_t version;
    uint32_t flags;
    uint32_t features;
  };
  struct KsuUidShouldUmountCmd {
    uint32_t uid;
    uint8_t should_umount;
  };
  struct KsuGetManagerUidCmd {
    uint32_t uid;
  };

  int scan_driver_fd() {
    DIR *dir = opendir("/proc/self/fd");
    if (!dir)
      return -1;
    int found = -1;
    for (dirent *ent; (ent = readdir(dir)) != nullptr;) {
      if (ent->d_name[0] == '.')
        continue;
      char *end = nullptr;
      long number = strtol(ent->d_name, &end, 10);
      if (!end || *end != '\0' || number < 0 || number > INT32_MAX)
        continue;
      char path[64];
      char target[128];
      snprintf(path, sizeof(path), "/proc/self/fd/%s", ent->d_name);
      ssize_t n = readlink(path, target, sizeof(target) - 1);
      if (n <= 0)
        continue;
      target[n] = '\0';
      if (strstr(target, "[ksu_driver]")) {
        found = static_cast<int>(number);
        break;
      }
    }
    closedir(dir);
    return found;
  }

  Method method_ = Method::None;
  int fd_ = -1;
};

struct Context {
  bool enabled = false;
  uint32_t owner = YZ_ROOT_OWNER_UAPI_NONE;
  uint32_t manager_appid = YZ_POLICY_REFRESH_ALL;
  uint32_t generation = 0;
  int control_fd = -1;
  bool complete = false;
  bool default_should_umount = false;
  std::map<uint32_t, bool> decisions;
  SourceStamp stamp;
  KsuClient ksu;
};

Context g;

const char *policy_path() {
  if (g.owner == YZ_ROOT_OWNER_UAPI_KERNELSU)
    return kKsuAllowlist;
  if (g.owner == YZ_ROOT_OWNER_UAPI_KERNELPATCH)
    return kApatchConfig;
  return nullptr;
}

bool parse_ksu_uids(std::set<uint32_t> *uids) {
  std::vector<uint8_t> data;
  if (!read_all(kKsuAllowlist, &data) || data.size() < 8)
    return false;

  uint32_t magic = 0;
  uint32_t version = 0;
  memcpy(&magic, data.data(), sizeof(magic));
  memcpy(&version, data.data() + sizeof(magic), sizeof(version));
  if (magic != kKsuAllowlistMagic || version < 2 || version > 4)
    return false;
  size_t record_size = version >= 4 ? kKsuV4ProfileSize :
                                      kKsuLegacyProfileSize;
  if ((data.size() - 8) % record_size != 0 ||
      (data.size() - 8) / record_size > YZ_POLICY_CACHE_MAX_ENTRIES)
    return false;

  for (size_t offset = 8; offset < data.size(); offset += record_size) {
    const uint8_t *record = data.data() + offset;
    if (!memchr(record + kKsuKeyOffset, '\0', kKsuKeySize))
      return false;
    int32_t uid = -1;
    memcpy(&uid, record + kKsuUidOffset, sizeof(uid));
    if (uid < 0)
      return false;
    uids->insert(static_cast<uint32_t>(uid));
  }
  return true;
}

bool parse_apatch(std::map<uint32_t, bool> *decisions) {
  std::ifstream file(kApatchConfig);
  if (!file.is_open())
    return false;

  std::string line;
  if (!std::getline(file, line))
    return false;
  bool valid = true;
  size_t count = 0;
  while (std::getline(file, line)) {
    if (line.empty())
      continue;
    auto fields = split_csv(line);
    uint32_t exclude = 0;
    uint32_t uid = 0;
    if (fields.size() < 4 || !parse_u32(fields[1], &exclude) ||
        !parse_u32(fields[3], &uid)) {
      valid = false;
      continue;
    }
    (*decisions)[uid] = (*decisions)[uid] || exclude != 0;
    if (++count > YZ_POLICY_CACHE_MAX_ENTRIES)
      return false;
  }
  return valid;
}

bool push_cache() {
  if (g.control_fd < 0 ||
      g.decisions.size() > YZ_POLICY_CACHE_MAX_ENTRIES)
    return false;

  int fd = static_cast<int>(syscall(SYS_memfd_create, "yz_policy_cache",
                                    MFD_CLOEXEC | MFD_ALLOW_SEALING));
  if (fd < 0) {
    log_message("memfd_create failed: %s", strerror(errno));
    return false;
  }

  yz_policy_cache_header header {};
  header.magic = YZ_POLICY_CACHE_MAGIC;
  header.version = YZ_POLICY_CACHE_VERSION;
  header.header_size = sizeof(header);
  header.entry_size = sizeof(yz_policy_cache_entry);
  header.flags = g.complete ? YZ_POLICY_CACHE_F_COMPLETE : 0;
  header.owner = g.owner;
  header.generation = ++g.generation;
  header.count = static_cast<uint32_t>(g.decisions.size());
  header.default_should_umount = g.default_should_umount ? 1 : 0;
  header.manager_appid = g.manager_appid;

  bool ok = write_all(fd, &header, sizeof(header));
  for (const auto &[uid, decision] : g.decisions) {
    yz_policy_cache_entry entry {uid, decision ? 1U : 0U};
    if (ok)
      ok = write_all(fd, &entry, sizeof(entry));
  }
  if (ok)
    ok = fcntl(fd, F_ADD_SEALS,
               F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL) == 0;
  if (ok) {
    yz_policy_cache_cmd cmd {fd, 0};
    ok = ioctl(g.control_fd, YZ_IOCTL_SET_POLICY_CACHE, &cmd) == 0;
  }
  if (!ok)
    log_message("cache handoff failed: %s", strerror(errno));
  close(fd);
  return ok;
}

bool refresh_ksu() {
  if (!g.ksu.initialize()) {
    log_message("KernelSU userspace ioctl/prctl unavailable");
    return false;
  }

  std::set<uint32_t> uids;
  bool parsed = parse_ksu_uids(&uids);
  uids.insert(kKsuDefaultProfileUid);
  uids.insert(kKsuWebViewZygoteUid);

  std::map<uint32_t, bool> next;
  bool all_queries = true;
  bool default_decision = false;
  for (uint32_t uid : uids) {
    bool decision = false;
    if (!g.ksu.query(uid, &decision)) {
      all_queries = false;
      continue;
    }
    next[uid] = decision;
    if (uid == kKsuDefaultProfileUid)
      default_decision = decision;
  }

  uint32_t manager_appid = YZ_POLICY_REFRESH_ALL;
  bool manager_known = g.ksu.manager_appid(&manager_appid);
  g.decisions = std::move(next);
  g.manager_appid = manager_appid;
  g.default_should_umount = default_decision;
  g.complete = parsed && all_queries && manager_known &&
               g.decisions.count(kKsuDefaultProfileUid) != 0;
  return push_cache();
}

bool refresh_apatch() {
  std::map<uint32_t, bool> next;
  bool parsed = parse_apatch(&next);
  g.decisions = std::move(next);
  g.manager_appid = YZ_POLICY_REFRESH_ALL;
  g.default_should_umount = false;
  g.complete = parsed;
  return push_cache();
}

} // namespace

bool setup(int control_fd, const yz_root_status_cmd &status) {
  g.control_fd = control_fd;
  g.owner = status.owner;
  g.enabled = (status.flags & YZ_ROOT_STATUS_POLICY_FALLBACK) != 0;
  if (!g.enabled)
    return true;
  if (g.owner != YZ_ROOT_OWNER_UAPI_KERNELSU &&
      g.owner != YZ_ROOT_OWNER_UAPI_KERNELPATCH)
    return false;
  return refresh(true);
}

bool active() { return g.enabled; }

bool refresh(bool force) {
  if (!g.enabled)
    return true;
  const char *path = policy_path();
  SourceStamp current;
  bool have_current = path && read_stamp(path, &current);
  if (!force && have_current && same_stamp(current, g.stamp))
    return true;

  bool ok = false;
  if (g.owner == YZ_ROOT_OWNER_UAPI_KERNELSU)
    ok = refresh_ksu();
  else if (g.owner == YZ_ROOT_OWNER_UAPI_KERNELPATCH)
    ok = refresh_apatch();
  if (ok && have_current)
    g.stamp = current;
  log_message("refresh owner=%u generation=%u entries=%zu complete=%u result=%u",
              g.owner, g.generation, g.decisions.size(),
              g.complete ? 1 : 0, ok ? 1 : 0);
  return ok;
}

bool query_uid(uint32_t uid, bool *should_umount) {
  if (!g.enabled || !should_umount)
    return false;
  (void)refresh(false);

  if (g.owner == YZ_ROOT_OWNER_UAPI_KERNELSU) {
    bool decision = false;
    if (!g.ksu.query(uid, &decision))
      return false;
    g.decisions[uid] = decision;
    (void)push_cache();
    *should_umount = decision;
    return true;
  }

  if (g.owner == YZ_ROOT_OWNER_UAPI_KERNELPATCH) {
    auto it = g.decisions.find(uid);
    if (it != g.decisions.end()) {
      *should_umount = it->second;
      return true;
    }
    if (g.complete) {
      *should_umount = g.default_should_umount;
      return true;
    }
  }
  return false;
}

void handle_refresh_request(uint32_t uid) {
  if (!g.enabled)
    return;
  if (uid == YZ_POLICY_REFRESH_ALL) {
    (void)refresh(true);
    return;
  }
  bool ignored = false;
  (void)query_uid(uid, &ignored);
}

const char *source_name() {
  if (!g.enabled)
    return "kernel";
  if (g.owner == YZ_ROOT_OWNER_UAPI_KERNELSU)
    return "userspace-ksu-api";
  if (g.owner == YZ_ROOT_OWNER_UAPI_KERNELPATCH)
    return "userspace-apatch-config";
  return "unavailable";
}

} // namespace yzpolicy
