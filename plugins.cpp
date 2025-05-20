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

#include "binder/binder.h"
#include "procrank/procrank.h"
#include "memory/cma.h"
#include "devicetree/dts.h"
#include "memory/memblock.h"
#include "memory/reserved.h"
#include "memory/iomem.h"
#include "memory/vmalloc.h"
#include "memory/dmabuf/cmd_buf.h"
#include "memory/slub.h"
#include "memory/zram.h"
#include "memory/swap.h"
#include "memory/buddy.h"
#include "device_driver/dd.h"
#include "pageowner/pageowner.h"
#include "workqueue/workqueue.h"
#include "partition/filesystem.h"
#include "cpu/cpuinfo.h"
#include "rtb/rtb.h"
#include "property/prop.h"
#include "logcat/Logcat_parser.h"
#include "coredump/coredump.h"
#include "thermal/thermal.h"
#include "memory/meminfo.h"
#include "watchdog/wdt.h"
#include "pagecache/pageinfo.h"
#include "debugimage/debugimage.h"
#include "ipc/ipc.h"
#include "regulator/regulator.h"
#include "icc/icc.h"
#include "clock/clock.h"
#include "pstore/pstore.h"
#include "sysinfo/sys.h"

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
std::shared_ptr<DDriver>    DDriver::instance = nullptr;
std::shared_ptr<DmaIon>     DmaIon::instance = nullptr;
std::shared_ptr<Workqueue>  Workqueue::instance = nullptr;
std::shared_ptr<Reserved>   Reserved::instance = nullptr;
std::shared_ptr<IoMem>      IoMem::instance = nullptr;
std::shared_ptr<Vmalloc>    Vmalloc::instance = nullptr;
std::shared_ptr<FileSystem> FileSystem::instance = nullptr;
std::shared_ptr<Pageowner>  Pageowner::instance = nullptr;
std::shared_ptr<Buddy>      Buddy::instance = nullptr;
std::shared_ptr<Zram>       Zram::instance = nullptr;
std::shared_ptr<Swap>       Swap::instance = nullptr;
std::shared_ptr<Prop>       Prop::instance = nullptr;
std::shared_ptr<Logcat_Parser>  Logcat_Parser::instance = nullptr;
std::shared_ptr<Rtb>        Rtb::instance = nullptr;
std::shared_ptr<CpuInfo>    CpuInfo::instance = nullptr;
std::shared_ptr<Coredump>   Coredump::instance = nullptr;
std::shared_ptr<Thermal>    Thermal::instance = nullptr;
std::shared_ptr<Meminfo>    Meminfo::instance = nullptr;
std::shared_ptr<Watchdog>   Watchdog::instance = nullptr;
std::shared_ptr<Pageinfo>   Pageinfo::instance = nullptr;
std::shared_ptr<DebugImage> DebugImage::instance = nullptr;
std::shared_ptr<IPCLog>     IPCLog::instance = nullptr;
std::shared_ptr<Regulator>  Regulator::instance = nullptr;
std::shared_ptr<ICC>        ICC::instance = nullptr;
std::shared_ptr<Clock>      Clock::instance = nullptr;
std::shared_ptr<Pstore>     Pstore::instance = nullptr;
std::shared_ptr<SysInfo>    SysInfo::instance = nullptr;

extern "C" void __attribute__((constructor)) plugin_init(void) {
    // fprintf(fp, "plugin_init\n");
    Binder::instance = std::make_shared<Binder>();
    Slub::instance = std::make_shared<Slub>();
    Procrank::instance = std::make_shared<Procrank>();
    Cma::instance = std::make_shared<Cma>();
    Dts::instance = std::make_shared<Dts>();
    Memblock::instance = std::make_shared<Memblock>();
    DDriver::instance = std::make_shared<DDriver>();
    DmaIon::instance = std::make_shared<DmaIon>();
    Workqueue::instance = std::make_shared<Workqueue>();
    Reserved::instance = std::make_shared<Reserved>();
    IoMem::instance = std::make_shared<IoMem>();
    Vmalloc::instance = std::make_shared<Vmalloc>();
    FileSystem::instance = std::make_shared<FileSystem>();
    Pageowner::instance = std::make_shared<Pageowner>();
    Buddy::instance = std::make_shared<Buddy>();
    Zram::instance = std::make_shared<Zram>();
    Swap::instance = std::make_shared<Swap>(Zram::instance);
    Prop::instance = std::make_shared<Prop>(Swap::instance);
    Logcat_Parser::instance = std::make_shared<Logcat_Parser>(Swap::instance, Prop::instance);
    Rtb::instance = std::make_shared<Rtb>();
    CpuInfo::instance = std::make_shared<CpuInfo>();
    Coredump::instance = std::make_shared<Coredump>(Swap::instance);
    Thermal::instance = std::make_shared<Thermal>();
    Meminfo::instance = std::make_shared<Meminfo>();
    Watchdog::instance = std::make_shared<Watchdog>();
    Pageinfo::instance = std::make_shared<Pageinfo>();
    DebugImage::instance = std::make_shared<DebugImage>();
    IPCLog::instance = std::make_shared<IPCLog>();
    Regulator::instance = std::make_shared<Regulator>();
    ICC::instance = std::make_shared<ICC>();
    Clock::instance = std::make_shared<Clock>();
    Pstore::instance = std::make_shared<Pstore>();
    SysInfo::instance = std::make_shared<SysInfo>();

    static struct command_table_entry command_table[] = {
        { &Binder::instance->cmd_name[0], &Binder::wrapper_func, Binder::instance->cmd_help, 0 },
        { &Slub::instance->cmd_name[0], &Slub::wrapper_func, Slub::instance->cmd_help, 0 },
        { &Procrank::instance->cmd_name[0], &Procrank::wrapper_func, Procrank::instance->cmd_help, 0 },
        { &Cma::instance->cmd_name[0], &Cma::wrapper_func, Cma::instance->cmd_help, 0 },
        { &Dts::instance->cmd_name[0], &Dts::wrapper_func, Dts::instance->cmd_help, 0 },
        { &Memblock::instance->cmd_name[0], &Memblock::wrapper_func, Memblock::instance->cmd_help, 0 },
        { &DDriver::instance->cmd_name[0], &DDriver::wrapper_func, DDriver::instance->cmd_help, 0 },
        { &DmaIon::instance->cmd_name[0], &DmaIon::wrapper_func, DmaIon::instance->cmd_help, 0 },
        { &Workqueue::instance->cmd_name[0], &Workqueue::wrapper_func, Workqueue::instance->cmd_help, 0 },
        { &Reserved::instance->cmd_name[0], &Reserved::wrapper_func, Reserved::instance->cmd_help, 0 },
        { &IoMem::instance->cmd_name[0], &IoMem::wrapper_func, IoMem::instance->cmd_help, 0 },
        { &Vmalloc::instance->cmd_name[0], &Vmalloc::wrapper_func, Vmalloc::instance->cmd_help, 0 },
        { &FileSystem::instance->cmd_name[0], &FileSystem::wrapper_func, FileSystem::instance->cmd_help, 0 },
        { &Pageowner::instance->cmd_name[0], &Pageowner::wrapper_func, Pageowner::instance->cmd_help, 0 },
        { &Buddy::instance->cmd_name[0], &Buddy::wrapper_func, Buddy::instance->cmd_help, 0 },
        { &Zram::instance->cmd_name[0], &Zram::wrapper_func, Zram::instance->cmd_help, 0 },
        { &Swap::instance->cmd_name[0], &Swap::wrapper_func, Swap::instance->cmd_help, 0 },
        { &Prop::instance->cmd_name[0], &Prop::wrapper_func, Prop::instance->cmd_help, 0 },
        { &Logcat_Parser::instance->cmd_name[0], &Logcat_Parser::wrapper_func, Logcat_Parser::instance->cmd_help, 0 },
        { &Rtb::instance->cmd_name[0], &Rtb::wrapper_func, Rtb::instance->cmd_help, 0 },
        { &CpuInfo::instance->cmd_name[0], &CpuInfo::wrapper_func, CpuInfo::instance->cmd_help, 0 },
        { &Coredump::instance->cmd_name[0], &Coredump::wrapper_func, Coredump::instance->cmd_help, 0 },
        { &Thermal::instance->cmd_name[0], &Thermal::wrapper_func, Thermal::instance->cmd_help, 0 },
        { &Meminfo::instance->cmd_name[0], &Meminfo::wrapper_func, Meminfo::instance->cmd_help, 0 },
        { &Watchdog::instance->cmd_name[0], &Watchdog::wrapper_func, Watchdog::instance->cmd_help, 0 },
        { &Pageinfo::instance->cmd_name[0], &Pageinfo::wrapper_func, Pageinfo::instance->cmd_help, 0 },
        { &DebugImage::instance->cmd_name[0], &DebugImage::wrapper_func, DebugImage::instance->cmd_help, 0 },
        { &IPCLog::instance->cmd_name[0], &IPCLog::wrapper_func, IPCLog::instance->cmd_help, 0 },
        { &Regulator::instance->cmd_name[0], &Regulator::wrapper_func, Regulator::instance->cmd_help, 0 },
        { &ICC::instance->cmd_name[0], &ICC::wrapper_func, ICC::instance->cmd_help, 0 },
        { &Clock::instance->cmd_name[0], &Clock::wrapper_func, Clock::instance->cmd_help, 0 },
        { &Pstore::instance->cmd_name[0], &Pstore::wrapper_func, Pstore::instance->cmd_help, 0 },
        { &SysInfo::instance->cmd_name[0], &SysInfo::wrapper_func, SysInfo::instance->cmd_help, 0 },
        { NULL }
    };
    register_extension(command_table);
}

extern "C" void __attribute__((destructor)) plugin_fini(void) {
    // fprintf(fp, "plugin_fini\n");
    Binder::instance.reset();
    Slub::instance.reset();
    Procrank::instance.reset();
    Cma::instance.reset();
    Dts::instance.reset();
    Memblock::instance.reset();
    DDriver::instance.reset();
    DmaIon::instance.reset();
    Workqueue::instance.reset();
    Reserved::instance.reset();
    IoMem::instance.reset();
    Vmalloc::instance.reset();
    FileSystem::instance.reset();
    Pageowner::instance.reset();
    Buddy::instance.reset();
    Zram::instance.reset();
    Swap::instance.reset();
    Prop::instance.reset();
    Logcat_Parser::instance.reset();
    Rtb::instance.reset();
    CpuInfo::instance.reset();
    Coredump::instance.reset();
    Thermal::instance.reset();
    Meminfo::instance.reset();
    Watchdog::instance.reset();
    Pageinfo::instance.reset();
    DebugImage::instance.reset();
    IPCLog::instance.reset();
    Regulator::instance.reset();
    ICC::instance.reset();
    Clock::instance.reset();
    Pstore::instance.reset();
    SysInfo::instance.reset();
}

#endif // BUILD_TARGET_TOGETHER

#pragma GCC diagnostic pop
