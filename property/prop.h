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
