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

#ifndef HEAP_DEFS_H_
#define HEAP_DEFS_H_

#include "plugin.h"
#include "dmabuf.h"

class Heap : public ParserPlugin {
protected:
    std::shared_ptr<Dmabuf> dmabuf_ptr;

public:
    Heap(std::shared_ptr<Dmabuf> dmabuf);
    void cmd_main(void) override;
    void init_offset(void) override;
    void init_command(void) override;
    virtual std::vector<ulong> get_heaps()=0;
    virtual void parser_heaps()=0;
    virtual void print_heaps()=0;
    virtual void print_system_heap_pool()=0;
    virtual void print_heap(std::string name)=0;
};

#endif // HEAP_DEFS_H_
