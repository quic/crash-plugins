// Copyright (c) 2024-2025 Qualcomm Innovation Center, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Clear
#include "binder/binder.h"
#include "procrank/procrank.h"
#include "memory/cma.h"
#include "devicetree/dts.h"
#include "memory/memblock.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpointer-arith"

#ifdef BUILD_TARGET_TOGETHER
extern "C" void plugin_init(void);
extern "C" void plugin_fini(void);

std::unique_ptr<Binder>     Binder::instance = nullptr;
std::unique_ptr<Procrank>   Procrank::instance = nullptr;
std::unique_ptr<Cma>        Cma::instance = nullptr;
std::unique_ptr<Dts>        Dts::instance = nullptr;
std::unique_ptr<Memblock>   Memblock::instance = nullptr;

extern "C" void __attribute__((constructor)) plugin_init(void) {
    // fprintf(fp, "plugin_init\n");
    Binder::instance = std::make_unique<Binder>();
    Procrank::instance = std::make_unique<Procrank>();
    Cma::instance = std::make_unique<Cma>();
    Dts::instance = std::make_unique<Dts>();
    Memblock::instance = std::make_unique<Memblock>();
    static struct command_table_entry command_table[] = {
	    { &Binder::instance->cmd_name[0], &Binder::wrapper_func, Binder::instance->cmd_help, 0 },
	    { &Procrank::instance->cmd_name[0], &Procrank::wrapper_func, Procrank::instance->cmd_help, 0 },
	    { &Cma::instance->cmd_name[0], &Cma::wrapper_func, Cma::instance->cmd_help, 0 },
	    { &Dts::instance->cmd_name[0], &Dts::wrapper_func, Dts::instance->cmd_help, 0 },
	    { &Memblock::instance->cmd_name[0], &Memblock::wrapper_func, Memblock::instance->cmd_help, 0 },
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
}

#endif // BUILD_TARGET_TOGETHER

#pragma GCC diagnostic pop
