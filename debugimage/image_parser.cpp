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

#include "image_parser.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpointer-arith"


void ImageParser::cmd_main(void) {

}

ImageParser::ImageParser(){

}

uint32_t ImageParser::get_vcpu_index(uint32_t affinity) {
    return 0;
}

uint64_t ImageParser::createMask(int a, int b) {
    uint64_t r = 0;
    for (int i = a; i <= b; ++i) {
        r |= 1ULL << i;
    }
    return r;
}

uint64_t ImageParser::pac_ignore(uint64_t data) {
    if (data == 0 || !BITS64()) {
        return data;
    }
#if defined(ARM64)
    uint64_t kernel_pac_mask = createMask(machdep->machspec->VA_BITS_ACTUAL, 63);
    if ((data & kernel_pac_mask) == kernel_pac_mask || (data & kernel_pac_mask) == 0) {
        return data;
    }
    // When address tagging is used
    // The PAC field is Kernel[63:bottom_PAC_bit],User[54:bottom_PAC_bit].
    // In the PAC field definitions, bottom_PAC_bit == 64-TCR_ELx.TnSZ,
    // TCR_ELx.TnSZ is set to 25. so 64-25=39
    uint64_t result = kernel_pac_mask | data;
    return result;
#endif
    return data;
}

std::string ImageParser::get_cmm_path(std::string name, bool secure){
    std::string reg_file_path;
    char buffer[PATH_MAX];
    if (getcwd(buffer, sizeof(buffer)) != nullptr) {
        reg_file_path = buffer;
    }
    char filename[32];
    if (secure){
        snprintf(filename, sizeof(filename), "secure_world_%s_regs.cmm",name.c_str());
    }else{
        snprintf(filename, sizeof(filename), "%s_regs.cmm",name.c_str());
    }
    reg_file_path += "/" + std::string(filename);
    // fprintf(fp, "reg_file_path:%s\n", reg_file_path.c_str());
    return reg_file_path;
}
#pragma GCC diagnostic pop
