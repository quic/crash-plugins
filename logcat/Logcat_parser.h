// Copyright (c) 2024-2025 Qualcomm Innovation Center, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Clear

#ifndef LOGCAT_PARSER_DEFS_H_
#define LOGCAT_PARSER_DEFS_H_

#include "plugin.h"
#include "logcatR.h"
#include "logcatS.h"
#include "logcat.h"
#include <dirent.h> // for directory operations
#include <sys/stat.h> // for file status
#include "memory/swapinfo.h"
#include "property/propinfo.h"

class Logcat_Parser : public PaserPlugin {
private:
    std::unique_ptr<Logcat> logcat_ptr;
    std::shared_ptr<Swapinfo> swap_ptr;
    std::shared_ptr<PropInfo> prop_ptr;
    std::vector<symbol> symbol_list = {
        {"libc.so", ""},
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
