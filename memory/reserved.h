// Copyright (c) 2024-2025 Qualcomm Innovation Center, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Clear

#ifndef RESERVED_DEFS_H_
#define RESERVED_DEFS_H_

#include "plugin.h"
#include "devicetree/devicetree.h"

enum class Type{
    NO_MAP,
    REUSABLE,
    UNKNOW,
};

struct reserved_mem {
    ulong addr;
    std::string name;
    ulonglong base;
    ulonglong size;
    bool status;
    Type type;
};

class Reserved : public PaserPlugin {
public:
    std::shared_ptr<Devicetree> dts;
    std::vector<std::shared_ptr<reserved_mem>> mem_list;
    Reserved();

    void cmd_main(void) override;
    void parser_reserved_mem();
    void print_reserved_mem();
    DEFINE_PLUGIN_INSTANCE(Reserved)
};


#endif // RESERVED_DEFS_H_
