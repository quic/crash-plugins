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

#ifndef WDT_DEFS_H_
#define WDT_DEFS_H_

#include "plugin.h"

class Watchdog : public ParserPlugin {
public:
    Watchdog();

    void cmd_main(void) override;
    void parser_msm_wdt();
    void parser_upstream_wdt();
    std::string nstoSec(ulonglong ns);
    ulong get_wdt_by_cdev();
    int get_task_cpu(ulong task_addr, ulong thread_info_addr);
    ulong get_thread_info_addr(ulong task_addr);
    DEFINE_PLUGIN_INSTANCE(Watchdog)
};

#endif // WDT_DEFS_H_
