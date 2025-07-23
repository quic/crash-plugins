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

class Reserved : public ParserPlugin {
private:
    std::shared_ptr<Devicetree> dts;
    std::vector<std::shared_ptr<reserved_mem>> mem_list;

    void parser_reserved_mem();
    void print_reserved_mem();

public:
    Reserved();
    void cmd_main(void) override;
    void init_offset(void) override;
    void init_command(void) override;
    DEFINE_PLUGIN_INSTANCE(Reserved)
};


#endif // RESERVED_DEFS_H_
