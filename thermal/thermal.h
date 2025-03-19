// Copyright (c) 2024-2025 Qualcomm Innovation Center, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Clear

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

class Thermal : public PaserPlugin {
public:
    std::vector<std::shared_ptr<zone_dev>> zone_list;
    Thermal();

    void print_zone_device();
    void print_zone_device(std::string dev_name);
    void cmd_main(void) override;
    void parser_thrermal_zone();
    DEFINE_PLUGIN_INSTANCE(Thermal)
};

#endif // THERMAL_DEFS_H_
