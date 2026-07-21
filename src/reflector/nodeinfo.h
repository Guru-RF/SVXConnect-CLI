/* SPDX-License-Identifier: GPL-3.0-or-later
 * SVXConnect-CLI — Copyright (C) 2026 Joeri Van Dooren
 */
#ifndef SVX_NODEINFO_H
#define SVX_NODEINFO_H

#include <stddef.h>
#include "common/config.h"

/* Build the MsgNodeInfo JSON document the reflector portal displays.
 * Returns the length written (excluding the NUL). */
size_t nodeinfo_build_json(char *out, size_t cap, const svx_config *cfg);

#endif
