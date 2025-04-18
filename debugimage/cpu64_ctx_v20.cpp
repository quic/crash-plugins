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

#include "cpu64_ctx_v20.h"
#include "debugimage.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpointer-arith"

Cpu64_Context_V20::Cpu64_Context_V20(){
    field_init(msm_dump_cpu_ctx,cpu_type);
    cpu_type_offset = field_offset(msm_dump_cpu_ctx,cpu_type);
    if (cpu_type_offset == -1){
        cpu_type_offset = 0x0;
    }
    field_init(msm_dump_cpu_ctx,ctx_type);
    ctx_type_offset = field_offset(msm_dump_cpu_ctx,ctx_type);
    if (ctx_type_offset == -1){
        ctx_type_offset = 0x4;
    }
    field_init(msm_dump_cpu_ctx,cpu_id);
    cpu_id_offset = field_offset(msm_dump_cpu_ctx,cpu_id);
    if (cpu_id_offset == -1){
        cpu_id_offset = 0xC;
    }
    field_init(msm_dump_cpu_ctx,affinity);
    cpu_index_offset = field_offset(msm_dump_cpu_ctx,affinity);
    if (cpu_index_offset == -1){
        cpu_index_offset = 0x10;
    }
    field_init(msm_dump_cpu_ctx,machine_id);
    machine_id_offset = field_offset(msm_dump_cpu_ctx,machine_id);
    if (machine_id_offset == -1){
        machine_id_offset = 0x14;
    }
    field_init(msm_dump_cpu_ctx,registers);
    registers_offset = field_offset(msm_dump_cpu_ctx,registers);
    if (registers_offset == -1){
        registers_offset = 0x20;
    }
    field_init(msm_dump_cpu_ctx,num_register_sets);
    regset_num_register_offset = field_offset(msm_dump_cpu_ctx,num_register_sets);
    if (regset_num_register_offset == -1){
        regset_num_register_offset = 0x1C;
    }
    field_init(msm_dump_cpu_register_entry,regset_id);
    regset_id_offset = field_offset(msm_dump_cpu_register_entry,regset_id);
    if (regset_id_offset == -1){
        regset_id_offset = 0x0;
    }
    field_init(msm_dump_cpu_register_entry,regset_addr);
    regset_addr_offset = field_offset(msm_dump_cpu_register_entry,regset_addr);
    if (regset_addr_offset == -1){
        regset_addr_offset = 0x8;
    }
    struct_init(msm_dump_cpu_register_entry);
    registers_size = struct_size(msm_dump_cpu_register_entry);
    if (registers_size == -1){
        registers_size = 0x10;
    }
    struct_init(msm_dump_aarch64_gprs);
    regset_size = struct_size(msm_dump_aarch64_gprs);
    if (regset_size == -1){
        regset_size = 0x110;
    }
    dump_regset_ids[0] = "MSM_DUMP_REGSET_IDS_INVALID";
    dump_regset_ids[16] = "MSM_DUMP_REGSET_IDS_AARCH64_GPRS";
    dump_regset_ids[17] = "MSM_DUMP_REGSET_IDS_AARCH64_NEON";
    dump_regset_ids[18] = "MSM_DUMP_REGSET_IDS_AARCH64_SVE";
    dump_regset_ids[19] = "MSM_DUMP_REGSET_IDS_AARCH64_SYSREGS_EL0";
    dump_regset_ids[20] = "MSM_DUMP_REGSET_IDS_AARCH64_EL1";
    dump_regset_ids[21] = "MSM_DUMP_REGSET_IDS_AARCH64_EL2";
    dump_regset_ids[22] = "MSM_DUMP_REGSET_IDS_AARCH64_VM_EL2";
    dump_regset_ids[23] = "MSM_DUMP_REGSET_IDS_AARCH64_EL3";
    dump_regset_ids[24] = "MSM_DUMP_REGSET_IDS_AARCH64_DBG_EL1";
}

void Cpu64_Context_V20::compute_pc(sysdbg_cpu64_ctx_2_0_gprs_t reg,sysdbg_neon128_registers_t neon_reg){

}

void Cpu64_Context_V20::print_stack(std::shared_ptr<Dump_entry> entry_ptr){

}

void Cpu64_Context_V20::generate_cmm(std::shared_ptr<Dump_entry> entry_ptr){
    int32_t affinity = read_uint(entry_ptr->data_addr + cpu_index_offset,"affinity",false);
    int32_t cpu_type = read_uint(entry_ptr->data_addr + cpu_type_offset,"cpu_type",false);
    int32_t ctx_type = read_uint(entry_ptr->data_addr + ctx_type_offset,"ctx_type",false);
    int32_t num_register = read_uint(entry_ptr->data_addr + regset_num_register_offset,"num_register",false);

    std::vector<std::shared_ptr<regset_t>> regset_list;
    uint64_t registers_addr = entry_ptr->data_addr + registers_offset;
    for (size_t i = 0; i < num_register; i++){
        uint64_t addr = registers_addr + i * registers_size;
        int32_t regset_id = read_uint(addr + regset_id_offset,"regset_id",false);
        if (regset_id == 0){
            break;
        }
        std::shared_ptr<regset_t> regset_ptr = std::make_shared<regset_t>();
        regset_ptr->id = regset_id;
        regset_ptr->name = dump_regset_ids[regset_id];
        regset_ptr->start_addr = read_ulonglong(addr + regset_addr_offset,"regset_addr",false);
        regset_ptr->end_addr = regset_ptr->start_addr + regset_size;
        regset_list.push_back(regset_ptr);
    }
}

#pragma GCC diagnostic pop
