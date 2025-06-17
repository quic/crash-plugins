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

#ifndef CLOCK_DEFS_H_
#define CLOCK_DEFS_H_

#include "plugin.h"

struct clk_provider {
    ulong addr;
    std::string name;
    std::vector<ulong> core_list;
};

class Clock : public ParserPlugin {
private:
    std::vector<std::shared_ptr<clk_provider>> provider_list;

public:
    Clock();

    void parser_clk_simple(std::shared_ptr<clk_provider> prov_ptr,ulong data);
    void parser_clk_hw_simple(std::shared_ptr<clk_provider> prov_ptr,ulong data);
    void parser_clk_rpmh(std::shared_ptr<clk_provider> prov_ptr, ulong data);
    void parser_clk_of_msm_provider(std::shared_ptr<clk_provider> prov_ptr, ulong data);
    void parser_clk_onecell(std::shared_ptr<clk_provider> prov_ptr,ulong data);
    void parser_clk_spmi_pmic(std::shared_ptr<clk_provider> prov_ptr,ulong data);
    void parser_rpm_smd_clk(std::shared_ptr<clk_provider> prov_ptr,ulong data);
    void parser_clk_qcom_cc(std::shared_ptr<clk_provider> prov_ptr,ulong data);
    void parser_clk_virtio(std::shared_ptr<clk_provider> prov_ptr,ulong data);
    void parser_clk_core(ulong addr);
    void print_enable_clock();
    void print_disable_clock();
    void print_prepare_clock();
    void cmd_main(void) override;
    void parser_clk_providers();
    void print_clk_providers();
    void print_clk_tree();
    DEFINE_PLUGIN_INSTANCE(Clock)
};

#endif // CLOCK_DEFS_H_
