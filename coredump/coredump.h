// Copyright (c) 2024-2025 Qualcomm Innovation Center, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Clear
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
    std::shared_ptr<Swapinfo> swap_ptr;
    bool is_compat = false;
    bool debug = false;

public:
    Coredump();
    Coredump(std::shared_ptr<Swapinfo> swap);
    void init_command();
    void cmd_main(void) override;
    DEFINE_PLUGIN_INSTANCE(Coredump)
};

#endif // COREDUMP_DEFS_H_
