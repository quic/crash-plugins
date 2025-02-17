// Copyright (c) 2024-2025 Qualcomm Innovation Center, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Clear

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

class IoMem : public PaserPlugin {
public:
    std::vector<std::shared_ptr<resource>> iomem_list;
    IoMem();
    void cmd_main(void) override;
    void parser_iomem();
    void print_iomem(std::vector<std::shared_ptr<resource>>& res_list,int level);
    void parser_resource(ulong addr,std::vector<std::shared_ptr<resource>>& res_list);
    DEFINE_PLUGIN_INSTANCE(IoMem)
};


#endif // IOMEM_DEFS_H_
