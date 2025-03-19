// Copyright (c) 2024-2025 Qualcomm Innovation Center, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Clear

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
                struct_init(android_event_header_t);
                if (struct_size(android_event_header_t) <= 0){
                    fprintf(fp, "Not load logd symbol, Please run logcat -s <symbol path> load it !\n");
                    return;
                }
                field_init(prop_info,name);
                if (field_offset(prop_info,name) == -1){
                    fprintf(fp, "Not load libc.so symbol, Please run logcat -s <symbol path> load it !\n");
                    return;
                }
                if (logcat_ptr.get() == nullptr){
                    std::string version = prop_ptr->get_prop("ro.build.version.sdk");
                    if (version.empty() || version == ""){
                        version = prop_ptr->get_prop("ro.vndk.version");
                    }
                    if (version.empty() || version == ""){
                        fprintf(fp, "Can't get Android version from this Dump !\n");
                        return;
                    }
                    int android_ver = 30;
                    try {
                        android_ver = std::stoi(version);
                        fprintf(fp, "android_version is : %d !\n",android_ver);
                    } catch (const std::invalid_argument& e) {
                        std::cerr << "Invalid argument: " << e.what() << std::endl;
                        return;
                    } catch (const std::out_of_range& e) {
                        std::cerr << "Out of range: " << e.what() << std::endl;
                        return;
                    }
                    if (android_ver >= 31) { //Android12 S
                        logcat_ptr = std::make_unique<LogcatS>(swap_ptr);
                    }else if (android_ver >= 30){ //Android11 R
                        logcat_ptr = std::make_unique<LogcatR>(swap_ptr);
                        fprintf(fp, "LogcatR!\n");
                    }else if (android_ver >= 29){ //Android10 Q
                        logcat_ptr = std::make_unique<LogcatR>(swap_ptr);
                        // logcat_ptr = std::make_unique<LogcatQ>(swap_ptr);
                    }else if (android_ver >= 28){ //Android9 Pie
                        logcat_ptr = std::make_unique<LogcatR>(swap_ptr);
                        // logcat_ptr = std::make_unique<LogcatPie>(swap_ptr);
                    }else if (android_ver >= 27){ //Android8 Oreo
                        logcat_ptr = std::make_unique<LogcatR>(swap_ptr);
                        // logcat_ptr = std::make_unique<LogcatOreo>(swap_ptr);
                    }else if (android_ver >= 26){ //Android7 Nougat
                        logcat_ptr = std::make_unique<LogcatR>(swap_ptr);
                        // logcat_ptr = std::make_unique<LogcatNougat>(swap_ptr);
                    }else{
                        fprintf(fp, "Not support for this Android version !\n");
                        return;
                    }
                }
                if (logcat_ptr.get() != nullptr){
                    for (auto& symbol : symbol_list) {
                        if (symbol.name == "logd" && !symbol.path.empty()){
                            logcat_ptr->logd_symbol = symbol.path;
                            break;
                        }
                    }
                    if (logcat_ptr->logd_symbol.empty()){
                        fprintf(fp, "Not load logd symbol, Please run logcat -s <symbol path> load it !\n");
                        return;
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
