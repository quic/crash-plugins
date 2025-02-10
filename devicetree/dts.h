// Copyright (c) 2024-2025 Qualcomm Innovation Center, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Clear

#ifndef DTS_DEFS_H_
#define DTS_DEFS_H_

#include "plugin.h"
#include "devicetree/devicetree.h"

class Dts : public Devicetree {
private:

public:
    Dts();
    static const int DTS_SHOW = 0x0001;
    static const int DTS_ADDR = 0x0002;
    static const int DTS_PATH = 0x0004;
    static const int DTB_MAX_SIZE = 0x100000;
    void cmd_main(void) override;
    void print_ddr_info();
    void read_dtb(std::string& path);
    void print_node(std::shared_ptr<device_node> node_ptr,int level,int flag);
    void print_node(std::shared_ptr<device_node> node_ptr,int flag);
    void print_properties(std::vector<std::shared_ptr<Property>> props,int level,bool is_symbol,int flag);
    DEFINE_PLUGIN_INSTANCE(Dts)
};


#endif // DTS_DEFS_H_
