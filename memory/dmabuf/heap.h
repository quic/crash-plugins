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

#ifndef HEAP_DEFS_H_
#define HEAP_DEFS_H_

#include "plugin.h"
#include "dmabuf.h"

class Heap : public PaserPlugin {
protected:
    std::shared_ptr<Dmabuf> dmabuf_ptr;

public:
    Heap(std::shared_ptr<Dmabuf> dmabuf);
    virtual std::vector<ulong> get_heaps()=0;
    virtual void parser_heaps()=0;
    virtual void print_heaps()=0;
    virtual void print_heap(std::string name)=0;
    void cmd_main(void) override;
};

#endif // HEAP_DEFS_H_
