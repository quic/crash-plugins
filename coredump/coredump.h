/**
 * Copyright (c) 2024-2025 Qualcomm Innovation Center, Inc. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef COREDUMP_DEFS_H_
#define COREDUMP_DEFS_H_

#include "plugin.h"
#include "core.h"
#if defined(ARM)
#include "arm/arm.h"
#endif

#if defined(ARM64)
#include "arm/arm64.h"
#include "arm/compat.h"
#endif

class Coredump : public PaserPlugin {
private:
    std::shared_ptr<Core> core_ptr;
    std::shared_ptr<Core> compat_core_ptr;
    std::shared_ptr<Swapinfo> swap_ptr;
    bool is_compat = false;
    bool debug = false;

public:
    Coredump();
    Coredump(std::shared_ptr<Swapinfo> swap);
    void init_command();
    void cmd_main(void) override;
    void print_proc_mapping(int pid);
    void generate_coredump(int pid);
    DEFINE_PLUGIN_INSTANCE(Coredump)
};

#endif // COREDUMP_DEFS_H_
