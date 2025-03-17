// Copyright (c) 2024-2025 Qualcomm Innovation Center, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Clear
#include "binder/binder.h"
#include "procrank/procrank.h"
#include "memory/cma.h"
#include "devicetree/dts.h"
#include "memory/memblock.h"
#include "memory/reserved.h"
#include "memory/iomem.h"
#include "memory/vmalloc.h"
#include "memory/slub.h"
#include "memory/zram.h"
#include "memory/swap.h"
#include "memory/buddy.h"
#include "workqueue/workqueue.h"
#include "partition/filesystem.h"
#include "rtb/rtb.h"
#include "property/prop.h"
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpointer-arith"

#ifdef BUILD_TARGET_TOGETHER
extern "C" void plugin_init(void);
extern "C" void plugin_fini(void);

std::shared_ptr<Binder>     Binder::instance = nullptr;
std::shared_ptr<Slub>       Slub::instance = nullptr;
std::shared_ptr<Procrank>   Procrank::instance = nullptr;
std::shared_ptr<Cma>        Cma::instance = nullptr;
std::shared_ptr<Dts>        Dts::instance = nullptr;
std::shared_ptr<Memblock>   Memblock::instance = nullptr;
std::shared_ptr<Workqueue>  Workqueue::instance = nullptr;
std::shared_ptr<Reserved>   Reserved::instance = nullptr;
std::shared_ptr<IoMem>      IoMem::instance = nullptr;
std::shared_ptr<Vmalloc>    Vmalloc::instance = nullptr;
std::shared_ptr<FileSystem> FileSystem::instance = nullptr;
std::shared_ptr<Buddy>      Buddy::instance = nullptr;
std::shared_ptr<Zram>       Zram::instance = nullptr;
std::shared_ptr<Swap>       Swap::instance = nullptr;
std::shared_ptr<Prop>       Prop::instance = nullptr;
std::shared_ptr<Rtb>        Rtb::instance = nullptr;

extern "C" void __attribute__((constructor)) plugin_init(void) {
    // fprintf(fp, "plugin_init\n");
    Binder::instance = std::make_shared<Binder>();

    Cma::instance = std::make_shared<Cma>();
    Dts::instance = std::make_shared<Dts>();
    Memblock::instance = std::make_shared<Memblock>();
    Workqueue::instance = std::make_shared<Workqueue>();
    Reserved::instance = std::make_shared<Reserved>();
    IoMem::instance = std::make_shared<IoMem>();
    Slub::instance = std::make_shared<Slub>();
    Vmalloc::instance = std::make_shared<Vmalloc>();
    FileSystem::instance = std::make_shared<FileSystem>();
    Buddy::instance = std::make_shared<Buddy>();
    Rtb::instance = std::make_shared<Rtb>();

    Zram::instance = std::make_shared<Zram>();
    Swap::instance = std::make_shared<Swap>(Zram::instance);
    Prop::instance = std::make_shared<Prop>(Swap::instance);
    Procrank::instance = std::make_shared<Procrank>(Swap::instance);

    static struct command_table_entry command_table[] = {
        { &Binder::instance->cmd_name[0], &Binder::wrapper_func, Binder::instance->cmd_help, 0 },
        { &Procrank::instance->cmd_name[0], &Procrank::wrapper_func, Procrank::instance->cmd_help, 0 },
        { &Cma::instance->cmd_name[0], &Cma::wrapper_func, Cma::instance->cmd_help, 0 },
        { &Dts::instance->cmd_name[0], &Dts::wrapper_func, Dts::instance->cmd_help, 0 },
        { &Memblock::instance->cmd_name[0], &Memblock::wrapper_func, Memblock::instance->cmd_help, 0 },
        { &Workqueue::instance->cmd_name[0], &Workqueue::wrapper_func, Workqueue::instance->cmd_help, 0 },
        { &Reserved::instance->cmd_name[0], &Reserved::wrapper_func, Reserved::instance->cmd_help, 0 },
        { &IoMem::instance->cmd_name[0], &IoMem::wrapper_func, IoMem::instance->cmd_help, 0 },
        { &Vmalloc::instance->cmd_name[0], &Vmalloc::wrapper_func, Vmalloc::instance->cmd_help, 0 },
	{ &Slub::instance->cmd_name[0], &Slub::wrapper_func, Slub::instance->cmd_help, 0 },
	{ &FileSystem::instance->cmd_name[0], &FileSystem::wrapper_func, FileSystem::instance->cmd_help, 0 },
	{ &Buddy::instance->cmd_name[0], &Buddy::wrapper_func, Buddy::instance->cmd_help, 0 },
	{ &Rtb::instance->cmd_name[0], &Rtb::wrapper_func, Rtb::instance->cmd_help, 0 },
	{ &Zram::instance->cmd_name[0], &Zram::wrapper_func, Zram::instance->cmd_help, 0 },
	{ &Swap::instance->cmd_name[0], &Swap::wrapper_func, Swap::instance->cmd_help, 0 },
	{ &Prop::instance->cmd_name[0], &Prop::wrapper_func, Prop::instance->cmd_help, 0 },
        { NULL }
    };
    register_extension(command_table);
}

extern "C" void __attribute__((destructor)) plugin_fini(void) {
    // fprintf(fp, "plugin_fini\n");
    Binder::instance.reset();
    Procrank::instance.reset();
    Cma::instance.reset();
    Dts::instance.reset();
    Memblock::instance.reset();
    Workqueue::instance.reset();
    Reserved::instance.reset();
    IoMem::instance.reset();
    Vmalloc::instance.reset();
    FileSystem::instance.reset();
    Buddy::instance.reset();
    Rtb::instance.reset();
    Slub::instance.reset();
    Zram::instance.reset();
    Swap::instance.reset();
    Prop::instance.reset();
}

#endif // BUILD_TARGET_TOGETHER

#pragma GCC diagnostic pop
