/* SPDX-License-Identifier: Apache-2.0 */
/*
 * YukiZygisk - Root-policy parser fixture tests.
 *
 * License: Apache-2.0
 *
 * Author: Anatdx
 */

#include "../root_policy.cpp"

#include <cassert>
#include <filesystem>

namespace {

void put_u32(std::vector<uint8_t> *data, size_t offset, uint32_t value) {
  assert(offset + sizeof(value) <= data->size());
  memcpy(data->data() + offset, &value, sizeof(value));
}

void write_bytes(const char *path, const std::vector<uint8_t> &data) {
  std::ofstream file(path, std::ios::binary | std::ios::trunc);
  assert(file.is_open());
  file.write(reinterpret_cast<const char *>(data.data()),
             static_cast<std::streamsize>(data.size()));
  assert(file.good());
}

void test_ksu_version(uint32_t version, size_t record_size) {
  std::vector<uint8_t> data(8 + record_size * 2, 0);
  put_u32(&data, 0, 0x7f4b5355U);
  put_u32(&data, 4, version);

  size_t first = 8;
  memcpy(data.data() + first + 4, "com.example.app", 16);
  put_u32(&data, first + 260, 10420);

  size_t second = first + record_size;
  memcpy(data.data() + second + 4, "$", 2);
  put_u32(&data, second + 260, 9999);
  write_bytes("/data/adb/ksu/.allowlist", data);

  std::set<uint32_t> uids;
  assert(yzpolicy::parse_ksu_uids(&uids));
  assert(uids.size() == 2);
  assert(uids.count(10420) == 1);
  assert(uids.count(9999) == 1);

  data[0] ^= 0xff;
  write_bytes("/data/adb/ksu/.allowlist", data);
  uids.clear();
  assert(!yzpolicy::parse_ksu_uids(&uids));
}

void test_apatch_csv() {
  std::ofstream file("/data/adb/ap/package_config", std::ios::trunc);
  assert(file.is_open());
  file << "pkg,exclude,allow,uid,to_uid,sctx\n";
  file << "\"com.example,quoted\",1,0,10411,0,u:r:untrusted_app:s0\n";
  file << "com.example.allowed,0,1,10420,0,u:r:su:s0\n";
  file << "com.example.duplicate,0,0,10411,0,u:r:untrusted_app:s0\n";
  file.close();

  std::map<uint32_t, bool> decisions;
  assert(yzpolicy::parse_apatch(&decisions));
  assert(decisions.size() == 2);
  assert(decisions.at(10411));
  assert(!decisions.at(10420));

  std::ofstream broken("/data/adb/ap/package_config",
                       std::ios::app);
  broken << "broken,row\n";
  broken.close();
  decisions.clear();
  assert(!yzpolicy::parse_apatch(&decisions));
  assert(decisions.at(10411));
}

} // namespace

int main() {
  std::filesystem::create_directories("/data/adb/ksu");
  std::filesystem::create_directories("/data/adb/ap");
  test_ksu_version(2, 776);
  test_ksu_version(4, 784);
  test_apatch_csv();
  return 0;
}
