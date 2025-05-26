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

#ifndef LOGCAT_PARSER_DEFS_H_
#define LOGCAT_PARSER_DEFS_H_

#include "plugin.h"
#include "logcatR.h"
#include "logcatS.h"
#include "logcatLE.h"
#include "logcat.h"
#include <dirent.h> // for directory operations
#include <sys/stat.h> // for file status
#include "memory/swapinfo.h"
#include "property/propinfo.h"

class Logcat_Parser : public ParserPlugin {
private:
    std::unique_ptr<Logcat> logcat_ptr;
    std::shared_ptr<Swapinfo> swap_ptr;
    std::shared_ptr<PropInfo> prop_ptr;
    std::vector<symbol> symbol_list = {
        {"libc.so", ""}, // for LE, the lib is libc.so.6
        {"logd", ""},
    };

public:
    Logcat_Parser();
    Logcat_Parser(std::shared_ptr<Swapinfo> swap,std::shared_ptr<PropInfo> prop);
    void init_command();
    void cmd_main(void) override;
    DEFINE_PLUGIN_INSTANCE(Logcat_Parser)
};

#endif // LOGCAT_PARSER_DEFS_H_
