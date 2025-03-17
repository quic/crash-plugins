// Copyright (c) 2024-2025 Qualcomm Innovation Center, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Clear

#ifndef PROP_DEFS_H_
#define PROP_DEFS_H_

#include "property/propinfo.h"

class Prop : public PropInfo {

public:
    Prop();
    Prop(std::shared_ptr<Swapinfo> swap);
    void init_command();
    void print_propertys();
    void cmd_main(void) override;
    DEFINE_PLUGIN_INSTANCE(Prop)
};

#endif // PROP_DEFS_H_
