/* SPDX-License-Identifier: Apache-2.0 */
/*
 * YukiZygisk - Userspace root-policy fallback.
 *
 * License: Apache-2.0
 *
 * Author: Anatdx
 */
#pragma once

#include "uapi/yukizygisk.h"

#include <cstdint>

namespace yzpolicy {

bool setup(int control_fd, const yz_root_status_cmd &status);
bool active();
bool refresh(bool force);
bool query_uid(uint32_t uid, bool *should_umount);
void handle_refresh_request(uint32_t uid);
const char *source_name();

} // namespace yzpolicy
