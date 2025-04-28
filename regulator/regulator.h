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

#ifndef REGULATOR_DEFS_H_
#define REGULATOR_DEFS_H_

#include "plugin.h"

struct voltage {
    int min_uV;
    int max_uV;
};

struct regulator {
    ulong addr;
    std::string name;
    int load;
    int enable_count;
    std::vector<std::shared_ptr<voltage>> voltages;
};

struct regulator_dev {
    ulong addr;
    ulong desc;
    ulong constraint;
    int32_t open_count;
    int32_t use_count;
    int32_t bypass_count;
    std::string name;
    int min_uV;
    int max_uV;
    int input_uV;
    std::vector<std::shared_ptr<regulator>> consumers;
};

class Regulator : public PaserPlugin {
private:
    std::vector<std::shared_ptr<regulator_dev>> regulator_list;
public:
    Regulator();

    std::vector<ulong> parser_device_list();
    void print_regulator_consumer(std::string reg_name);
    void print_regulator_info();
    void print_regulator_dev();
    void cmd_main(void) override;
    void parser_regulator_dev();
    DEFINE_PLUGIN_INSTANCE(Regulator)
};

#endif // REGULATOR_DEFS_H_
