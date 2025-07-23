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

#ifndef IOMEM_DEFS_H_
#define IOMEM_DEFS_H_

#include "plugin.h"
#include "devicetree/devicetree.h"

struct resource {
    ulong addr;
    ulong start;
    ulong end;
    std::string name;
    ulong flags;
    std::vector<std::shared_ptr<resource>> childs;
};

class IoMem : public ParserPlugin {
private:
    std::vector<std::shared_ptr<resource>> iomem_list;

    void parser_iomem();
    void print_iomem(std::vector<std::shared_ptr<resource>>& res_list,int level);
    void parser_resource(ulong addr,std::vector<std::shared_ptr<resource>>& res_list);

public:
    IoMem();
    void cmd_main(void) override;
    void init_offset(void) override;
    void init_command(void) override;
    DEFINE_PLUGIN_INSTANCE(IoMem)
};


#endif // IOMEM_DEFS_H_
