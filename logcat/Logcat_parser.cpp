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

#include "Logcat_parser.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpointer-arith"

#ifndef BUILD_TARGET_TOGETHER
DEFINE_PLUGIN_COMMAND(Logcat_Parser)
#endif

static const std::unordered_map<std::string, LOG_ID> stringToLogID = {
    {"main", MAIN},
    {"radio", RADIO},
    {"events", EVENTS},
    {"system", SYSTEM},
    {"crash", CRASH},
    {"stats", STATS},
    {"security", SECURITY},
    {"kernel", KERNEL},
    {"all", ALL}
};

void Logcat_Parser::cmd_main(void) {
    int c;
    std::string cppString;
    if (argcnt < 2) cmd_usage(pc->curcmd, SYNOPSIS);
    while ((c = getopt(argcnt, args, "b:s:")) != EOF) {
        switch(c) {
            case 'b':
            {
                if (logcat_ptr.get() == nullptr) {
                    int android_ver = 0;
                    struct task_context* tc = pid_to_context(1);
                    if (tc) {
                        if (strstr(tc->comm, "systemd")) { /* LE + LU */
                            Logcat::is_LE = true;
                        } else {
                            std::string version = prop_ptr->get_prop("ro.build.version.sdk");
                            if (version.empty()) {
                                version = prop_ptr->get_prop("ro.vndk.version");
                            }
                            if (version.empty()) {
                                fprintf(fp, "Can't get Android version from this dump!\n");
                                return;
                            }
                            try {
                                android_ver = std::stoi(version);
                            } catch (const std::exception& e) {
                                fprintf(fp, "logcat exception in: %s\n", e.what());
                                return;
                            }
                        }
                    } else {
                        fprintf(fp, "Using Android R to parse log!\n");
                        android_ver = 30;
                    }
                    fprintf(fp, "Android version is: %d!\n", android_ver);
                    if (Logcat::is_LE) {
                        logcat_ptr = std::make_unique<LogcatLE>(swap_ptr); // Android 8.0
                    } else {
                        if (android_ver >= 31) { // Android 12 S
                            logcat_ptr = std::make_unique<LogcatS>(swap_ptr);
                        } else { // Android 11 R
                            logcat_ptr = std::make_unique<LogcatR>(swap_ptr);
                        }
                    }
                }
                if (logcat_ptr.get() != nullptr){
                    for (auto& symbol : symbol_list) {
                        if (symbol.name == "logd" && !symbol.path.empty()){
                            logcat_ptr->logd_symbol = symbol.path;
                            break;
                        }
                    }
                    logcat_ptr->parser_logcat_log();
                    cppString.assign(optarg);
                    auto it = stringToLogID.find(cppString);
                    if (it != stringToLogID.end()) {
                        LOG_ID log_id = it->second;
                        logcat_ptr->print_logcat_log(log_id);
                    } else {
                        fprintf(fp, "Invalid string for LOG_ID: %s \n",optarg);
                    }
                }
            }
                break;
            case 's':
            {
                try {
                    cppString.assign(optarg);
                    if (cppString.empty()){
                        fprintf(fp, "invaild symbol path: %s\n",cppString.c_str());
                        return;
                    }
                    for (auto& symbol : symbol_list) {
                        std::string symbol_path = cppString;
                        if (load_symbols(symbol_path, symbol.name)){
                            symbol.path = symbol_path;
                            for (auto& prop_symbol : prop_ptr->symbol_list) {
                                if (prop_symbol.name == symbol.name ){
                                    prop_symbol.path = symbol_path;
                                    break;
                                }
                            }
                        }
                    }
                } catch (...) {
                    fprintf(fp, "invaild arg %s\n",optarg);
                }
            }
                break;
            default:
                argerrs++;
                break;
        }
    }
    if (argerrs){
        cmd_usage(pc->curcmd, SYNOPSIS);
    }
}

Logcat_Parser::Logcat_Parser(std::shared_ptr<Swapinfo> swap,std::shared_ptr<PropInfo> prop)
    : swap_ptr(swap),prop_ptr(prop){
    init_command();
}

Logcat_Parser::Logcat_Parser(){
    init_command();
    swap_ptr = std::make_shared<Swapinfo>();
    prop_ptr = std::make_shared<PropInfo>(swap_ptr);
    //print_table();
}

void Logcat_Parser::init_command(){
    cmd_name = "logcat";
    help_str_list={
        "logcat",                            /* command name */
        "dump logcat log information",        /* short description */
        "-s <symbol directory path>\n"
            "  logcat -b <log id>\n"
            "  This command dumps the logcat log info.",
        "\n",
        "EXAMPLES",
        "  Add logd symbol file:",
        "    %s> logcat -s xx/<symbol directory path>",
        "    Add symbol:xx/symbols/system/bin/logd succ",
        "\n",
        "  Display logcat log:",
        "    %s> logcat -b all",
        "    %s> logcat -b main",
        "    %s> logcat -b system",
        "    %s> logcat -b radio",
        "    %s> logcat -b crash",
        "    %s> logcat -b events",
        "\n",
    };
    initialize();
}

#pragma GCC diagnostic pop
