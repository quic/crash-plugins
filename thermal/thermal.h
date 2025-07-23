/**
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
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

#ifndef THERMAL_DEFS_H_
#define THERMAL_DEFS_H_

#include "plugin.h"

struct cool_dev {
    ulong addr;
    int id;
    std::string name;
};

struct trip {
    ulong addr;
    int temp;
    std::vector<std::shared_ptr<cool_dev>> cool_list;
};

struct zone_dev {
    ulong addr;
    int id;
    std::string name;
    std::string governor;
    std::vector<std::shared_ptr<trip>> trip_list;
    int cur_temp;
    int last_temp;
};

class Thermal : public ParserPlugin {
private:
    std::vector<std::shared_ptr<zone_dev>> zone_list;

    void print_zone_device();
    void print_zone_device(std::string dev_name);
    void print_cooling_device();
    void parser_thrermal_zone();

public:
    Thermal();
    void init_offset(void) override;
    void init_command(void) override;
    void cmd_main(void) override;
    DEFINE_PLUGIN_INSTANCE(Thermal)
};

#endif // THERMAL_DEFS_H_
