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

#include "clock.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpointer-arith"

#ifndef BUILD_TARGET_TOGETHER
DEFINE_PLUGIN_COMMAND(Clock)
#endif

void Clock::cmd_main(void) {
    int c;
    std::string cppString;
    if (argcnt < 2) cmd_usage(pc->curcmd, SYNOPSIS);
    if (provider_list.size() == 0){
        parser_clk_providers();
    }
    while ((c = getopt(argcnt, args, "ctedp")) != EOF) {
        switch(c) {
            case 'c':
                print_clk_providers();
                break;
            case 't':
                print_clk_tree();
                break;
            case 'e':
                print_enable_clock();
                break;
            case 'd':
                print_disable_clock();
                break;
            case 'p':
                print_prepare_clock();
                break;
            default:
                argerrs++;
                break;
        }
    }
    if (argerrs)
        cmd_usage(pc->curcmd, SYNOPSIS);
}

Clock::Clock(){
    field_init(of_clk_provider,link);
    field_init(of_clk_provider,node);
    field_init(of_clk_provider,data);
    field_init(of_clk_provider,get);
    field_init(of_clk_provider,get_hw);
    struct_init(of_clk_provider);
    field_init(device_node,name);
    field_init(device_node,full_name);
    field_init(qcom_cc,rclks);
    field_init(qcom_cc,num_rclks);
    field_init(clk_regmap,hw);
    field_init(clk_hw,core);
    field_init(clk_core,name);
    field_init(clk,core);
    field_init(clk,clks_node);
    field_init(clk,dev);
    field_init(clk,dev_id);
    field_init(clk,con_id);
    field_init(clk_onecell_data,clks);
    field_init(clk_onecell_data,clk_num);
    field_init(rpm_smd_clk_desc,clks);
    field_init(rpm_smd_clk_desc,num_clks);
    field_init(clk_core,ops);
    field_init(clk_core,hw);
    field_init(clk_core,rate);
    field_init(clk_core,req_rate);
    field_init(clk_core,new_rate);
    field_init(clk_core,rpm_enabled);
    field_init(clk_core,boot_enabled);
    field_init(clk_core,enable_count);
    field_init(clk_core,prepare_count);
    field_init(clk_core,clks);
    field_init(clk_rpmh_desc,clks);
    field_init(clk_rpmh_desc,num_clks);
    struct_init(clk_core);
    struct_init(qcom_cc);
    struct_init(rpm_smd_clk_desc);
    struct_init(clk_rpmh_desc);
    cmd_name = "ccf";
    help_str_list={
        "ccf",                            /* command name */
        "dump clock information",        /* short description */
        "-c \n"
            "  ccf -t\n"
            "  ccf -e\n"
            "  ccf -d\n"
            "  ccf -p\n"
            "  This command dumps the clock info.",
        "\n",
        "EXAMPLES",
        "  Display all clock provider info:",
        "    %s> ccf -c",
        "    clk_provider: clock-controller",
        "       clk_core               rate   req_rate   new_rate rpm   boot  en    prep  clk_hw           Name",
        "       ffffff8017a8d600  1010.0MHZ   310.0MHZ  1010.0MHZ 0     1     1     1     ffffffd3034531a8 gpu_cc_pll0",
        "       ffffff8017a8dc00     0.0MHZ     0.0MHZ     0.0MHZ 0     0     0     0     ffffffd3034533f0 gpu_cc_crc_ahb_clk",
        "       ffffff8017a8dd00     0.0MHZ     0.0MHZ     0.0MHZ 0     0     0     0     ffffffd303453488 gpu_cc_cx_apb_clk",
        "       ffffff8017a8d900  1010.0MHZ    19.2MHZ  1010.0MHZ 0     0     0     0     ffffffd303453520 gpu_cc_cx_gfx3d_clk",
        "       ffffff8017a8d500  1010.0MHZ    19.2MHZ  1010.0MHZ 0     0     0     0     ffffffd3034535b8 gpu_cc_cx_gfx3d_slv_clk",
        "       ffffff8017a8df00    19.2MHZ    19.2MHZ     0.0MHZ 0     1     1     1     ffffffd3034532c0 gpu_cc_cx_gmu_clk",
        "\n",
        "  Display all clock provider and clock consumers by tree:",
        "    %s> ccf -t",
        "    clk_provider:clock-controller",
        "       clk_core:ffffff8017a8df00  gpu_cc_cx_gmu_clk                             19.2MHZ",
        "           clk:ffffff801625a000  device:5900000,kgsl-3d0",
        "       clk_core:ffffff8014936a00  gpu_cc_gmu_clk_src                            19.2MHZ",
        "       clk_core:ffffff80157fa700  gpu_cc_gx_cxo_clk                             19.2MHZ",
        "       clk_core:ffffff80157fa400  gpu_cc_gx_gfx3d_clk                           1010MHZ",
        "           clk:ffffff801a5b5f00  device:5900000,kgsl-3d0",
        "           clk:ffffff8022db7580  device:5900000,kgsl-3d0",
        "\n",
        "  Display all enable clock info:",
        "    %s> ccf -e",
        "    =============================================",
        "       Enable Clocks from of_clk_providers list",
        "    =============================================",
        "    clk_core         Name                                          Rate",
        "    ffffff801804ab00 dsi0_phy_pll_out_byteclk                      24.6847MHZ",
        "    ffffff801804aa00 dsi0_phy_pll_out_dsiclk                       8.22824MHZ",
        "    ffffff8017a8d600 gpu_cc_pll0                                   1010MHZ",
        "    ffffff8017a8df00 gpu_cc_cx_gmu_clk                             19.2MHZ",
        "    ffffff8017a8d300 gpu_cc_cxo_aon_clk_src                        19.2MHZ",
        "\n",
        "  Display all disable clock info:",
        "    %s> ccf -d",
        "    =============================================",
        "       Disabled Clocks from of_clk_providers list",
        "    =============================================",
        "    clk_core         Name                                          Rate",
        "    ffffff8015c11400 lpass_audio_hw_vote_clk                       0MHZ",
        "    ffffff8017a8dc00 gpu_cc_crc_ahb_clk                            0MHZ",
        "    ffffff8017a8dd00 gpu_cc_cx_apb_clk                             0MHZ",
        "    ffffff8017a8d900 gpu_cc_cx_gfx3d_clk                           1010MHZ",
        "\n",
        "  Display all prepare clock info:",
        "    %s> ccf -p",
        "    =============================================",
        "       Prepare Clocks from of_clk_providers list",
        "    =============================================",
        "    clk_core         Name                                          Rate",
        "    ffffff801804ab00 dsi0_phy_pll_out_byteclk                      24.6847MHZ",
        "    ffffff801804aa00 dsi0_phy_pll_out_dsiclk                       8.22824MHZ",
        "    ffffff8017a8d600 gpu_cc_pll0                                   1010MHZ",
        "    ffffff8017a8df00 gpu_cc_cx_gmu_clk                             19.2MHZ",
        "\n",
    };
    initialize();
}

void Clock::parser_clk_of_msm_provider(std::shared_ptr<clk_provider> prov_ptr,ulong data){
    fprintf(fp, "   parser_clk_of_msm_provider[%#lx]: \n", data);
}

void Clock::parser_clk_spmi_pmic(std::shared_ptr<clk_provider> prov_ptr,ulong data){
    fprintf(fp, "   parser_clk_spmi_pmic[%#lx]: \n", data);
}

void Clock::parser_clk_virtio(std::shared_ptr<clk_provider> prov_ptr,ulong data){
    fprintf(fp, "   parser_clk_virtio[%#lx]: \n", data);
}

void Clock::parser_clk_simple(std::shared_ptr<clk_provider> prov_ptr,ulong data){
    ulong clk_core = read_ulong(data + field_offset(clk,core),"core");
    if (!is_kvaddr(clk_core)) {
        return;
    }
    prov_ptr->core_list.push_back(clk_core);
}

void Clock::parser_clk_hw_simple(std::shared_ptr<clk_provider> prov_ptr,ulong data){
    ulong clk_core = read_ulong(data + field_offset(clk_hw,core),"core");
    if (!is_kvaddr(clk_core)) {
        return;
    }
    prov_ptr->core_list.push_back(clk_core);
}

void Clock::parser_clk_rpmh(std::shared_ptr<clk_provider> prov_ptr,ulong data){
    if(struct_size(clk_rpmh_desc) == -1){
        fprintf(fp, "pls load clk-rpmh.ko at first\n");
        return;
    }
    size_t clk_num = read_ulong(data + field_offset(clk_rpmh_desc,num_clks),"num_clks");
    ulong clks = read_ulong(data + field_offset(clk_rpmh_desc,clks),"clks");
    for (size_t i = 0; i < clk_num; i++){
        ulong clk_addr = clks + i * sizeof(void *);
        clk_addr = read_ulong(clk_addr,"clk");
        if (!is_kvaddr(clk_addr)) {
            continue;
        }
        ulong clk_core = read_ulong(clk_addr + field_offset(clk_hw,core),"core");
        if (!is_kvaddr(clk_core)) {
            continue;
        }
        prov_ptr->core_list.push_back(clk_core);
    }
}

void Clock::parser_clk_onecell(std::shared_ptr<clk_provider> prov_ptr,ulong data){
    size_t clk_num = read_ulong(data + field_offset(clk_onecell_data,clk_num),"clk_num");
    ulong clks = read_ulong(data + field_offset(clk_onecell_data,clks),"clks");
    for (size_t i = 0; i < clk_num; i++){
        ulong clk_addr = clks + i * sizeof(void *);
        clk_addr = read_ulong(clk_addr,"clk");
        if (!is_kvaddr(clk_addr)) {
            continue;
        }
        ulong clk_core = read_ulong(clk_addr + field_offset(clk,core),"core");
        if (!is_kvaddr(clk_core)) {
            continue;
        }
        prov_ptr->core_list.push_back(clk_core);
    }
}

void Clock::parser_rpm_smd_clk(std::shared_ptr<clk_provider> prov_ptr,ulong data){
    if(struct_size(rpm_smd_clk_desc) == -1){
        fprintf(fp, "pls load rpm_smd_clk_desc.ko at first\n");
        return;
    }
    size_t num_clks = read_ulong(data + field_offset(rpm_smd_clk_desc,num_clks),"num_clks");
    ulong clks = read_ulong(data + field_offset(rpm_smd_clk_desc,clks),"clks");
    for (size_t i = 0; i < num_clks; i++){
        ulong clk_addr = clks + i * sizeof(void *);
        clk_addr = read_ulong(clk_addr,"clk");
        if (!is_kvaddr(clk_addr)) {
            continue;
        }
        ulong clk_core = read_ulong(clk_addr + field_offset(clk_hw,core),"core");
        if (!is_kvaddr(clk_core)) {
            continue;
        }
        prov_ptr->core_list.push_back(clk_core);
    }
}

void Clock::parser_clk_qcom_cc(std::shared_ptr<clk_provider> prov_ptr,ulong data){
    if(struct_size(qcom_cc) == -1){
        fprintf(fp, "pls load clk-qcom.ko at first\n");
        return;
    }
    size_t num_rclks = read_ulong(data + field_offset(qcom_cc,num_rclks),"num_rclks");
    ulong rclks = read_ulong(data + field_offset(qcom_cc,rclks),"rclks");
    // fprintf(fp, "qcom_cc:%#lx num_rclks:%lu rclks:%#lx \n", data, num_rclks,rclks);
    for (size_t i = 0; i < num_rclks; i++){
        ulong clk_addr = rclks + i * sizeof(void *);
        clk_addr = read_ulong(clk_addr,"clk");
        if (!is_kvaddr(clk_addr)) {
            continue;
        }
        ulong clk_core = read_ulong(clk_addr + field_offset(clk_regmap,hw) + field_offset(clk_hw,core),"clk_core");
        if (!is_kvaddr(clk_core)) {
            continue;
        }
        prov_ptr->core_list.push_back(clk_core);
    }
}

void Clock::parser_clk_core(ulong addr){
    ulong name_addr = read_pointer(addr + field_offset(clk_core,name),"name addr");
    std::string core_name = "";
    if (is_kvaddr(name_addr)){
        core_name = read_cstring(name_addr,64, "name");
    }
    void *core_buf = read_struct(addr,"clk_core");
    if (!core_buf) {
        return;
    }
    ulong hw = ULONG(core_buf + field_offset(clk_core,hw));
    ulong rate = ULONG(core_buf + field_offset(clk_core,rate));
    ulong req_rate = ULONG(core_buf + field_offset(clk_core,req_rate));
    ulong new_rate = ULONG(core_buf + field_offset(clk_core,new_rate));
    bool rpm_enabled = BOOL(core_buf + field_offset(clk_core,rpm_enabled));
    bool boot_enabled = ULONG(core_buf + field_offset(clk_core,boot_enabled));
    int enable_count = UINT(core_buf + field_offset(clk_core,enable_count));
    int prepare_count = UINT(core_buf + field_offset(clk_core,prepare_count));
    FREEBUF(core_buf);
    std::ostringstream oss;
    oss << std::left << std::setw(VADDR_PRLEN)  << std::hex << addr << " "
        << std::right << std::setw(7)   << std::setfill(' ') << std::fixed << std::setprecision(1) << (double)rate/1000000 << "MHZ "
        << std::right << std::setw(7)   << std::setfill(' ') << std::fixed << std::setprecision(1) << (double)req_rate/1000000 << "MHZ "
        << std::right << std::setw(7)   << std::setfill(' ') << std::fixed << std::setprecision(1) << (double)new_rate/1000000 << "MHZ "
        << std::left << std::setw(5)    << std::dec << rpm_enabled << " "
        << std::left << std::setw(5)    << std::dec << boot_enabled << " "
        << std::left << std::setw(5)    << std::dec << enable_count << " "
        << std::left << std::setw(5)    << std::dec << prepare_count << " "
        << std::left << std::setw(VADDR_PRLEN) << std::hex << hw << " "
        << core_name;
    fprintf(fp, "   %s \n",oss.str().c_str());
}

void Clock::print_enable_clock(){
    fprintf(fp, "=============================================\n");
    fprintf(fp, "  Enable Clocks from of_clk_providers list\n");
    fprintf(fp, "=============================================\n");
    std::ostringstream oss_h;
    oss_h << std::left << std::setw(VADDR_PRLEN) << "clk_core"  << " "
          << std::left << std::setw(45) << "Name" << " "
          << std::left << "Rate";
    fprintf(fp, "%s \n",oss_h.str().c_str());
    for (const auto& provider : provider_list) {
        if (provider->core_list.size() == 0){
            continue;
        }
        for (const auto& core_addr : provider->core_list) {
            std::string core_name;
            ulong name_addr = read_pointer(core_addr + field_offset(clk_core,name),"name addr");
            if (is_kvaddr(name_addr)){
                core_name = read_cstring(name_addr,64, "name");
            }
            if (core_name.empty()){
                core_name = "";
            }
            ulong rate = read_ulong(core_addr + field_offset(clk_core,rate),"rate");
            int enable_count = read_uint(core_addr + field_offset(clk_core,enable_count),"enable");
            if(enable_count > 0){
                std::ostringstream oss;
                oss << std::left << std::setw(VADDR_PRLEN) << std::hex << core_addr << " "
                    << std::left << std::setw(45)  << core_name << " "
                    << std::left << std::dec << (double)rate/1000000 << "MHZ";
                fprintf(fp, "%s \n",oss.str().c_str());
            }
        }
    }
}

void Clock::print_disable_clock(){
    fprintf(fp, "=============================================\n");
    fprintf(fp, "  Disabled Clocks from of_clk_providers list\n");
    fprintf(fp, "=============================================\n");
    std::ostringstream oss_h;
    oss_h << std::left << std::setw(VADDR_PRLEN) << "clk_core"  << " "
          << std::left << std::setw(45) << "Name" << " "
          << std::left << "Rate";
    fprintf(fp, "%s \n",oss_h.str().c_str());
    for (const auto& provider : provider_list) {
        if (provider->core_list.size() == 0){
            continue;
        }
        for (const auto& core_addr : provider->core_list) {
            std::string core_name;
            ulong name_addr = read_pointer(core_addr + field_offset(clk_core,name),"name addr");
            if (is_kvaddr(name_addr)){
                core_name = read_cstring(name_addr,64, "name");
            }
            if (core_name.empty()){
                core_name = "";
            }
            ulong rate = read_ulong(core_addr + field_offset(clk_core,rate),"rate");
            int enable_count = read_uint(core_addr + field_offset(clk_core,enable_count),"enable");
            int prepare_count = read_uint(core_addr + field_offset(clk_core,prepare_count),"prepare");
            if(prepare_count == 0 && enable_count == 0){
                std::ostringstream oss;
                oss << std::left << std::setw(VADDR_PRLEN) << std::hex << core_addr << " "
                    << std::left << std::setw(45)  << core_name << " "
                    << std::left << std::dec << (double)rate/1000000 << "MHZ";
                fprintf(fp, "%s \n",oss.str().c_str());
            }
        }
    }
}

void Clock::print_prepare_clock(){
    fprintf(fp, "=============================================\n");
    fprintf(fp, "  Prepare Clocks from of_clk_providers list\n");
    fprintf(fp, "=============================================\n");
    std::ostringstream oss_h;
    oss_h << std::left << std::setw(VADDR_PRLEN) << "clk_core"  << " "
          << std::left << std::setw(45) << "Name" << " "
          << std::left << "Rate";
    fprintf(fp, "%s \n",oss_h.str().c_str());
    for (const auto& provider : provider_list) {
        if (provider->core_list.size() == 0){
            continue;
        }
        for (const auto& core_addr : provider->core_list) {
            std::string core_name;
            ulong name_addr = read_pointer(core_addr + field_offset(clk_core,name),"name addr");
            if (is_kvaddr(name_addr)){
                core_name = read_cstring(name_addr,64, "name");
            }
            if (core_name.empty()){
                core_name = "";
            }
            ulong rate = read_ulong(core_addr + field_offset(clk_core,rate),"rate");
            int prepare_count = read_uint(core_addr + field_offset(clk_core,prepare_count),"prepare");
            if(prepare_count > 0){
                std::ostringstream oss;
                oss << std::left << std::setw(VADDR_PRLEN) << std::hex << core_addr << " "
                    << std::left << std::setw(45)  << core_name << " "
                    << std::left << std::dec << (double)rate/1000000 << "MHZ";
                fprintf(fp, "%s \n",oss.str().c_str());
            }
        }
    }
}

void Clock::print_clk_tree(){
    int offset = field_offset(clk,clks_node);
    for (const auto& provider : provider_list) {
        if (provider->core_list.size() == 0){
            continue;
        }
        fprintf(fp, "clk_provider:%s\n",provider->name.c_str());
        for (const auto& core_addr : provider->core_list) {
            std::string core_name;
            ulong name_addr = read_pointer(core_addr + field_offset(clk_core,name),"name addr");
            if (is_kvaddr(name_addr)){
                core_name = read_cstring(name_addr,64, "name");
            }
            if (core_name.empty()){
                core_name = "";
            }
            ulong rate = read_ulong(core_addr + field_offset(clk_core,rate),"rate");
            std::ostringstream oss;
            oss << std::left << "clk_core:" << std::hex << core_addr << "  "
                << std::left << std::setw(45)  << core_name << " "
                << std::left << std::dec << (double)rate/1000000 << "MHZ";
            fprintf(fp, "   %s \n",oss.str().c_str());
            ulong hlist_head = core_addr + field_offset(clk_core,clks);
            for (const auto& clk_addr : for_each_hlist(hlist_head, offset)) {
                std::string dev_id;
                ulong dev_id_addr = read_pointer(clk_addr + field_offset(clk,dev_id),"dev_id addr");
                ulong con_id_addr = read_pointer(clk_addr + field_offset(clk,con_id),"con_id addr");
                if(!dev_id_addr && !con_id_addr) continue;
                if (is_kvaddr(dev_id_addr)){
                    dev_id = read_cstring(dev_id_addr,64, "dev_id");
                }
                if (dev_id.empty()){
                    dev_id = "";
                }
                fprintf(fp, "           clk:%lx  --> device:%s \n",clk_addr, dev_id.c_str());
            }
        }
        fprintf(fp, "\n\n");
    }
}

void Clock::print_clk_providers(){
    for (const auto& provider : provider_list) {
        if (provider->core_list.size() == 0){
            continue;
        }
        fprintf(fp, "clk_provider: %s\n",provider->name.c_str());
        std::ostringstream oss;
        oss << std::left << std::setw(VADDR_PRLEN)   << "clk_core"  << " "
            << std::right << std::setw(10)   << "rate" << " "
            << std::right << std::setw(10)   << "req_rate" << " "
            << std::right << std::setw(10)   << "new_rate" << " "
            << std::left << std::setw(5)    << "rpm" << " "
            << std::left << std::setw(5)    << "boot" << " "
            << std::left << std::setw(5)    << "en" << " "
            << std::left << std::setw(5)    << "prep" << " "
            << std::left << std::setw(VADDR_PRLEN)    << "clk_hw" << " "
            << "Name";
        fprintf(fp, "   %s \n",oss.str().c_str());
        for (const auto& addr : provider->core_list) {
            parser_clk_core(addr);
        }
        fprintf(fp, "\n\n");
    }
}

void Clock::parser_clk_providers(){
    if (!csymbol_exists("of_clk_providers")){
        fprintf(fp, "of_clk_providers doesn't exist in this kernel!\n");
        return;
    }
    ulong list_head = csymbol_value("of_clk_providers");
    if (!is_kvaddr(list_head)) {
        fprintf(fp, "of_clk_providers address is invalid!\n");
        return;
    }
    int offset = field_offset(of_clk_provider, link);
    for (const auto& addr : for_each_list(list_head,offset)) {
        void *provider_buf = read_struct(addr,"of_clk_provider");
        if (!provider_buf) {
            continue;
        }
        std::shared_ptr<clk_provider> prov_ptr = std::make_shared<clk_provider>();
        prov_ptr->addr = addr;
        ulong node_addr = ULONG(provider_buf + field_offset(of_clk_provider,node));
        ulong get_addr = ULONG(provider_buf + field_offset(of_clk_provider,get));
        ulong get_hw_addr = ULONG(provider_buf + field_offset(of_clk_provider,get_hw));
        ulong data_addr = ULONG(provider_buf + field_offset(of_clk_provider,data));
        FREEBUF(provider_buf);
        if (is_kvaddr(node_addr)){
            ulong name_addr = read_pointer(node_addr,"name addr");
            if (is_kvaddr(name_addr)){
                prov_ptr->name = read_cstring(name_addr,64, "name");
            }
        }
        provider_list.push_back(prov_ptr);
        ulong offset;
        struct syment *sp;
        std::string func_name;
        if (is_kvaddr(get_addr)){
            sp = value_search(get_addr, &offset);
            if (sp){
                func_name = sp->name;
                // fprintf(fp, " %s\n",func_name.c_str());
                if (func_name.find("of_clk_src_simple_get") != std::string::npos) {
                    parser_clk_simple(prov_ptr,data_addr);
                }else if (func_name.find("of_clk_src_onecell_get") != std::string::npos){
                    parser_clk_onecell(prov_ptr,data_addr);
                }
            }else if (get_config_val("CONFIG_COMMON_CLK_MSM") == "y"){
                parser_clk_of_msm_provider(prov_ptr,data_addr);
            }
        }else if (is_kvaddr(get_hw_addr)){
            sp = value_search(get_hw_addr, &offset);
            if (sp){
                func_name = sp->name;
                // fprintf(fp, " %s\n",func_name.c_str());
                if (func_name.find("spmi_pmic_div_clk_hw_get") != std::string::npos) {
                    // TODO
                    parser_clk_spmi_pmic(prov_ptr,data_addr);
                }else if (func_name.find("qcom_cc_clk_hw_get") != std::string::npos){
                    parser_clk_qcom_cc(prov_ptr,data_addr);
                }else if (func_name.find("of_clk_hw_virtio_get") != std::string::npos){
                    // TODO
                    parser_clk_virtio(prov_ptr,data_addr);
                }else if (func_name.find("qcom_smdrpm_clk_hw_get") != std::string::npos){
                    parser_rpm_smd_clk(prov_ptr,data_addr);
                }else if (func_name.find("of_clk_hw_simple_get") != std::string::npos){
                    parser_clk_hw_simple(prov_ptr,data_addr);
                }else if (func_name.find("of_clk_rpmh_hw_get") != std::string::npos){
                    parser_clk_rpmh(prov_ptr,data_addr);
                }
            }
        }
    }
}

#pragma GCC diagnostic pop
