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

#include "iommu.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpointer-arith"

#ifndef BUILD_TARGET_TOGETHER
DEFINE_PLUGIN_COMMAND(IOMMU)
#endif

/**
 * Helper function: Get device name from device address
 */
std::string IOMMU::get_device_name(ulong dev_addr) {
    if (!is_kvaddr(dev_addr)) {
        return "Unknown";
    }

    ulong name_addr = read_pointer(dev_addr + field_offset(device, kobj) + field_offset(kobject, name), "device name addr");
    if (is_kvaddr(name_addr)) {
        return read_cstring(name_addr, 100, "device name");
    }
    return "Unknown";
}

/**
 * Helper function: Get enum name from enum list
 */
std::string IOMMU::get_enum_name(const std::map<std::string, ulong>& enum_list, ulong value) {
    for (const auto& pair : enum_list) {
        if (pair.second == value) {
            return pair.first;
        }
    }
    return std::to_string(value);
}

/**
 * Helper function: Print ARM SMMU configuration
 */
void IOMMU::print_arm_smmu_cfg(ulong cfg_addr, const std::map<std::string, ulong>& cbar_enum_list,
                                const std::map<std::string, ulong>& fmt_enum_list) {
    if (!is_kvaddr(cfg_addr)) {
        return;
    }

    uint8_t cbndx = read_uint(cfg_addr + field_offset(arm_smmu_cfg, cbndx), "cbndx") & 0xFF;
    uint16_t vmid = read_uint(cfg_addr + field_offset(arm_smmu_cfg, vmid), "vmid") & 0xFFFF;
    uint32_t procid = read_uint(cfg_addr + field_offset(arm_smmu_cfg, procid), "procid");
    uint32_t cbar_val = read_uint(cfg_addr + field_offset(arm_smmu_cfg, cbar), "cbar");
    uint32_t fmt_val = read_uint(cfg_addr + field_offset(arm_smmu_cfg, fmt), "fmt");

    std::string cbar_str = get_enum_name(cbar_enum_list, cbar_val);
    std::string fmt_str = get_enum_name(fmt_enum_list, fmt_val);

    std::ostringstream cfg_oss;
    cfg_oss << "             arm_smmu_cfg         : " << std::hex << std::showbase << cfg_addr << "\n";
    cfg_oss << "               cbndx              : " << std::dec << (unsigned)cbndx << "\n";
    cfg_oss << "               vmid               : " << std::dec << vmid << "\n";
    cfg_oss << "               procid             : " << std::dec << procid << "\n";
    cfg_oss << "               cbar               : " << cbar_str << "\n";
    cfg_oss << "               fmt                : " << fmt_str << "\n";
    PRINT("%s", cfg_oss.str().c_str());
}

/**
 * Helper function: Print context bank information
 */
void IOMMU::print_context_bank(ulong cb_addr, uint index, const std::map<std::string, ulong>& cbar_enum_list,
                                const std::map<std::string, ulong>& fmt_enum_list) {
    // Read ttbr array (2 x u64)
    ulong ttbr0 = read_ulong(cb_addr + field_offset(arm_smmu_cb, ttbr) + 0 * sizeof(uint64_t), "ttbr0");
    ulong ttbr1 = read_ulong(cb_addr + field_offset(arm_smmu_cb, ttbr) + 1 * sizeof(uint64_t), "ttbr1");

    // Read tcr array (2 x u32)
    uint tcr0 = read_uint(cb_addr + field_offset(arm_smmu_cb, tcr) + 0 * sizeof(uint32_t), "tcr0");
    uint tcr1 = read_uint(cb_addr + field_offset(arm_smmu_cb, tcr) + 1 * sizeof(uint32_t), "tcr1");

    // Read mair array (2 x u32)
    uint mair0 = read_uint(cb_addr + field_offset(arm_smmu_cb, mair) + 0 * sizeof(uint32_t), "mair0");
    uint mair1 = read_uint(cb_addr + field_offset(arm_smmu_cb, mair) + 1 * sizeof(uint32_t), "mair1");

    // Read sctlr (u32)
    uint sctlr = read_uint(cb_addr + field_offset(arm_smmu_cb, sctlr), "sctlr");

    // Read cfg pointer
    ulong cfg_addr = read_pointer(cb_addr + field_offset(arm_smmu_cb, cfg), "cfg");

    // Print context bank info
    PRINT("       CB[%02u]:ttbr[0]=%#lx ttbr[1]=%#lx tcr[0]=%#x tcr[1]=%#x mair[0]=%#x mair[1]=%#x sctlr=%#x\n",
          index, ttbr0, ttbr1, tcr0, tcr1, mair0, mair1, sctlr);

    // Print cfg if valid
    print_arm_smmu_cfg(cfg_addr, cbar_enum_list, fmt_enum_list);
}

/**
 * Main command entry point for IOMMU analysis
 */
void IOMMU::cmd_main(void) {
    if (argcnt < 2) {
        LOGD("Insufficient arguments provided, showing usage\n");
        cmd_usage(pc->curcmd, SYNOPSIS);
        return;
    }

    int argerrs = 0;
    int c;

    if (group_list.empty()) {
        parser_iommu_domains();
    }

    while ((c = getopt(argcnt, args, "lg")) != EOF) {
        switch(c) {
            case 'l':
                print_iommu_devices();
                break;
            case 'g':
                print_iommu_groups();
                break;
            default:
                LOGD("Unknown option: -%c\n", c);
                argerrs++;
                break;
        }
    }

    if (argerrs) {
        LOGE("Command line argument errors detected: %d\n", argerrs);
        cmd_usage(pc->curcmd, SYNOPSIS);
    }
}

/**
 * Print detailed information about an ARM SMMU device
 */
void IOMMU::print_arm_smmu_device(ulong arm_smmu_device_addr) {
    if (!is_kvaddr(arm_smmu_device_addr)) {
        return;
    }
    // Read device pointer and get device name
    ulong dev_addr = read_pointer(arm_smmu_device_addr + field_offset(arm_smmu_device, dev), "dev");
    std::string device_name = get_device_name(dev_addr);

    // Format and print the information
    std::ostringstream oss;
    oss << "arm_smmu_device:" << std::hex << std::showbase << arm_smmu_device_addr
        << " [" << device_name << "]\n";

    // Read and print base if field exists
    if (field_offset(arm_smmu_device, base) != -1) {
        ulong base = read_pointer(arm_smmu_device_addr + field_offset(arm_smmu_device, base), "base");
        oss << "    base                 : " << std::hex << std::showbase << base << "\n";
    }

    // Read and print ioaddr if field exists
    if (field_offset(arm_smmu_device, ioaddr) != -1) {
        ulong ioaddr = read_ulong(arm_smmu_device_addr + field_offset(arm_smmu_device, ioaddr), "ioaddr");
        oss << "    ioaddr               : " << std::hex << std::showbase << ioaddr << "\n";
    }

    // Read and print numpage if field exists
    if (field_offset(arm_smmu_device, numpage) != -1) {
        uint numpage = read_uint(arm_smmu_device_addr + field_offset(arm_smmu_device, numpage), "numpage");
        oss << "    numpage              : " << std::dec << numpage << "\n";
    }

    // Read and print pgshift if field exists
    if (field_offset(arm_smmu_device, pgshift) != -1) {
        uint pgshift = read_uint(arm_smmu_device_addr + field_offset(arm_smmu_device, pgshift), "pgshift");
        oss << "    pgshift              : " << std::dec << pgshift << "\n";
    }

    // Read and print features if field exists
    if (field_offset(arm_smmu_device, features) != -1) {
        uint features = read_uint(arm_smmu_device_addr + field_offset(arm_smmu_device, features), "features");
        oss << "    features             : " << std::hex << std::showbase << features << "\n";
    }

    // Read and print options if field exists
    if (field_offset(arm_smmu_device, options) != -1) {
        uint options = read_uint(arm_smmu_device_addr + field_offset(arm_smmu_device, options), "options");
        oss << "    options              : " << std::hex << std::showbase << options << "\n";
    }

    // Read and print version if field exists
    if (field_offset(arm_smmu_device, version) != -1) {
        uint version = read_uint(arm_smmu_device_addr + field_offset(arm_smmu_device, version), "version");
        std::map<std::string, ulong> version_enum_list = read_enum_list("arm_smmu_arch_version");
        std::string version_str = get_enum_name(version_enum_list, version);
        oss << "    version              : " << version_str << "\n";
    }

    // Read and print model if field exists
    if (field_offset(arm_smmu_device, model) != -1) {
        uint model = read_uint(arm_smmu_device_addr + field_offset(arm_smmu_device, model), "model");
        std::map<std::string, ulong> model_enum_list = read_enum_list("arm_smmu_implementation");
        std::string model_str = get_enum_name(model_enum_list, model);
        oss << "    model                : " << model_str << "\n";
    }

    // Read num_context_banks (needed for later logic)
    uint num_context_banks = 0;
    if (field_offset(arm_smmu_device, num_context_banks) != -1) {
        num_context_banks = read_uint(arm_smmu_device_addr + field_offset(arm_smmu_device, num_context_banks), "num_context_banks");
        oss << "    num_context_banks    : " << std::dec << num_context_banks << "\n";
    }

    // Read and print num_s2_context_banks if field exists
    if (field_offset(arm_smmu_device, num_s2_context_banks) != -1) {
        uint num_s2_context_banks = read_uint(arm_smmu_device_addr + field_offset(arm_smmu_device, num_s2_context_banks), "num_s2_context_banks");
        oss << "    num_s2_context_banks : " << std::dec << num_s2_context_banks << "\n";
    }

    // Read and print va_size if field exists
    if (field_offset(arm_smmu_device, va_size) != -1) {
        ulong va_size = read_ulong(arm_smmu_device_addr + field_offset(arm_smmu_device, va_size), "va_size");
        oss << "    va_size              : " << std::dec << va_size << "\n";
    }

    // Read and print ipa_size if field exists
    if (field_offset(arm_smmu_device, ipa_size) != -1) {
        ulong ipa_size = read_ulong(arm_smmu_device_addr + field_offset(arm_smmu_device, ipa_size), "ipa_size");
        oss << "    ipa_size             : " << std::dec << ipa_size << "\n";
    }

    // Read and print pa_size if field exists
    if (field_offset(arm_smmu_device, pa_size) != -1) {
        ulong pa_size = read_ulong(arm_smmu_device_addr + field_offset(arm_smmu_device, pa_size), "pa_size");
        oss << "    pa_size              : " << std::dec << pa_size << "\n";
    }

    // Read and print context bank information
    ulong cbs_addr = read_pointer(arm_smmu_device_addr + field_offset(arm_smmu_device, cbs), "cbs");
    if (is_kvaddr(cbs_addr) && num_context_banks > 0) {
        oss << "    Context Banks:\n";
        PRINT("%s", oss.str().c_str());
        // Load enum name maps for cfg fields
        std::map<std::string, ulong> cbar_enum_list = read_enum_list("arm_smmu_cbar_type");
        std::map<std::string, ulong> fmt_enum_list = read_enum_list("arm_smmu_context_fmt");
        size_t cb_size = field_offset(arm_smmu_cb, cfg) + sizeof(ulong);
        for (uint i = 0; i < num_context_banks; ++i) {
            ulong cb_addr = cbs_addr + i * cb_size;
            print_context_bank(cb_addr, i, cbar_enum_list, fmt_enum_list);
        }
        PRINT("\n");
    } else {
        oss << "\n";
        PRINT("%s", oss.str().c_str());
    }
}

void IOMMU::print_iommu_devices(void) {
    for (const auto& smmu_dev : arm_smmu_device_list) {
        print_arm_smmu_device(smmu_dev);
    }
}

void IOMMU::parser_iommu_domains(void) {
    std::set<ulong> processed_groups;

    for (auto& dev_ptr : for_each_device()) {
        if (!is_kvaddr(dev_ptr->addr)) {
            continue;
        }
        ulong iommu_group_addr = read_pointer(dev_ptr->addr + field_offset(device, iommu_group), "iommu_group");
        if (!is_kvaddr(iommu_group_addr)) {
            continue;
        }
        ulong iommu_domain_addr = read_pointer(iommu_group_addr + field_offset(iommu_group, domain), "iommu_domain");
        if (!is_kvaddr(iommu_domain_addr)) {
            continue;
        }
        domain_list.insert(iommu_domain_addr);
        if (processed_groups.find(iommu_group_addr) != processed_groups.end()) {
            continue;
        }
        processed_groups.insert(iommu_group_addr);

        GroupInfo info;
        info.iommu_domain_addr = iommu_domain_addr;
        info.iommu_group_addr = iommu_group_addr;
        info.group_id = read_int(iommu_group_addr + field_offset(iommu_group, id), "id");

        ulong arm_smmu_domain_addr = info.iommu_domain_addr - field_offset(arm_smmu_domain, domain);
        ulong arm_smmu_device_addr = read_pointer(arm_smmu_domain_addr + field_offset(arm_smmu_domain, smmu), "smmu");
        arm_smmu_device_list.insert(arm_smmu_device_addr);
        info.arm_smmu_device_addr = arm_smmu_device_addr;

        ulong devices_head = iommu_group_addr + field_offset(iommu_group, devices);
        info.devices = for_each_list(devices_head, field_offset(group_device, list));
        group_list.push_back(info);
    }

    std::sort(group_list.begin(), group_list.end(),
              [](const GroupInfo& a, const GroupInfo& b) {
                  return a.group_id < b.group_id;
              });
}

/**
 * Convert IOMMU domain type to string representation
 */
const char* IOMMU::domain_type_to_string(uint type) {
    #define __IOMMU_DOMAIN_PAGING   (1U << 0)
    #define __IOMMU_DOMAIN_DMA_API  (1U << 1)
    #define __IOMMU_DOMAIN_PT       (1U << 2)
    #define __IOMMU_DOMAIN_DMA_FQ   (1U << 3)
    #define __IOMMU_DOMAIN_SVA      (1U << 4)

    #define IOMMU_DOMAIN_BLOCKED    (0U)
    #define IOMMU_DOMAIN_IDENTITY   (__IOMMU_DOMAIN_PT)
    #define IOMMU_DOMAIN_UNMANAGED  (__IOMMU_DOMAIN_PAGING)
    #define IOMMU_DOMAIN_DMA        (__IOMMU_DOMAIN_PAGING | __IOMMU_DOMAIN_DMA_API)
    #define IOMMU_DOMAIN_DMA_FQ     (__IOMMU_DOMAIN_PAGING | __IOMMU_DOMAIN_DMA_API | __IOMMU_DOMAIN_DMA_FQ)
    #define IOMMU_DOMAIN_SVA        (__IOMMU_DOMAIN_SVA)

    switch (type) {
        case IOMMU_DOMAIN_BLOCKED:   return "IOMMU_DOMAIN_BLOCKED";
        case IOMMU_DOMAIN_IDENTITY:  return "IOMMU_DOMAIN_IDENTITY";
        case IOMMU_DOMAIN_UNMANAGED: return "IOMMU_DOMAIN_UNMANAGED";
        case IOMMU_DOMAIN_DMA:       return "IOMMU_DOMAIN_DMA";
        case IOMMU_DOMAIN_DMA_FQ:    return "IOMMU_DOMAIN_DMA_FQ";
        case IOMMU_DOMAIN_SVA:       return "IOMMU_DOMAIN_SVA";
        default:                     return "UNKNOWN";
    }
}

/**
 * Print detailed information about an IOMMU domain
 */
void IOMMU::print_iommu_domain_info(ulong domain_addr) {
    if (!is_kvaddr(domain_addr)) {
        return;
    }

    uint type = read_uint(domain_addr + field_offset(iommu_domain, type), "iommu_domain.type");
    ulong geom_addr = domain_addr + field_offset(iommu_domain, geometry);
    ulong aperture_start = read_ulong(geom_addr + field_offset(iommu_domain_geometry, aperture_start), "aperture_start");
    ulong aperture_end = read_ulong(geom_addr + field_offset(iommu_domain_geometry, aperture_end), "aperture_end");

    const char* type_str = domain_type_to_string(type);
    ulong arm_smmu_domain_addr = domain_addr - field_offset(arm_smmu_domain, domain);
    ulong freelist = read_pointer(arm_smmu_domain_addr + field_offset(arm_smmu_domain, freelist), "freelist");
    size_t page_count = for_each_list(freelist, field_offset(page, lru)).size();
    PRINT(" iommu_domain:%#lx(%zu) %s [%#016lx ~ %#016lx]\n",
          domain_addr, page_count, type_str, aperture_start, aperture_end);
}

void IOMMU::print_iommu_groups(void) {
    std::map<ulong, std::vector<GroupInfo>> smmu_to_groups;
    for (const auto& group : group_list) {
        smmu_to_groups[group.arm_smmu_device_addr].push_back(group);
    }

    for (const auto& smmu_pair : smmu_to_groups) {
        ulong arm_smmu_device_addr = smmu_pair.first;
        const auto& groups = smmu_pair.second;

        std::shared_ptr<device> arm_smmu_device_ptr = parser_device(
            read_pointer(arm_smmu_device_addr + field_offset(arm_smmu_device, dev), "device"));

        PRINT("arm_smmu_device:%#lx[%s]\n", arm_smmu_device_addr, arm_smmu_device_ptr->name.c_str());

        std::map<std::string, ulong> cbar_enum_list = read_enum_list("arm_smmu_cbar_type");
        std::map<std::string, ulong> fmt_enum_list = read_enum_list("arm_smmu_context_fmt");
        std::map<std::string, ulong> stage_enum_list = read_enum_list("arm_smmu_domain_stage");

        for (const auto& group : groups) {
            ulong arm_smmu_domain_addr = group.iommu_domain_addr - field_offset(arm_smmu_domain, domain);
            PRINT("    [%03d]iommu_group:%#lx ", group.group_id, group.iommu_group_addr);
            ulong cfg_base = arm_smmu_domain_addr + field_offset(arm_smmu_domain, cfg);
            uint8_t cbndx = read_uint(cfg_base + field_offset(arm_smmu_cfg, cbndx), "cbndx") & 0xFF;
            uint16_t vmid = read_uint(cfg_base + field_offset(arm_smmu_cfg, vmid), "vmid") & 0xFFFF;
            uint32_t procid = 0;
            if (field_offset(arm_smmu_cfg, procid) != -1){
                procid = read_uint(cfg_base + field_offset(arm_smmu_cfg, procid), "procid");
            }
            uint32_t cbar_val = read_uint(cfg_base + field_offset(arm_smmu_cfg, cbar), "cbar");
            uint32_t fmt_val = read_uint(cfg_base + field_offset(arm_smmu_cfg, fmt), "fmt");

            std::string cbar_str = get_enum_name(cbar_enum_list, cbar_val);
            std::string fmt_str = get_enum_name(fmt_enum_list, fmt_val);

            uint32_t stage_val = read_uint(arm_smmu_domain_addr + field_offset(arm_smmu_domain, stage), "stage");
            uint32_t secure_vmid = read_uint(arm_smmu_domain_addr + field_offset(arm_smmu_domain, secure_vmid), "secure_vmid");
            bool skip_tlb = read_bool(arm_smmu_domain_addr + field_offset(arm_smmu_domain, skip_tlb_management), "skip_tlb_management");

            std::string stage_str = get_enum_name(stage_enum_list, stage_val);
            print_iommu_domain_info(group.iommu_domain_addr);

            std::ostringstream domain_oss;
            domain_oss << "         arm_smmu_domain      : " << std::hex << std::showbase << arm_smmu_domain_addr << "\n";
            domain_oss << "           cbndx              : " << std::dec << (unsigned)cbndx << "\n";
            domain_oss << "           vmid               : " << std::dec << vmid << "\n";
            domain_oss << "           procid             : " << std::dec << procid << "\n";
            domain_oss << "           cbar               : " << cbar_str << "\n";
            domain_oss << "           fmt                : " << fmt_str << "\n";
            domain_oss << "           stage              : " << stage_str << "\n";
            domain_oss << "           secure_vmid        : " << std::dec << secure_vmid << "\n";
            domain_oss << "           skip_tlb           : " << (skip_tlb ? "true" : "false") << "\n";
            PRINT("%s", domain_oss.str().c_str());



            for (const auto& addr : group.devices) {
                ulong dev_addr = read_pointer(addr + field_offset(group_device, dev), "dev addr");
                ulong name_addr = read_pointer(addr + field_offset(group_device, name), "name addr");
                std::string name = read_cstring(name_addr, 100, "device name");
                ulong dev_iommu_addr = read_pointer(dev_addr + field_offset(device, iommu), "dev_iommu");
                uint sid = 0;
                if (is_kvaddr(dev_iommu_addr)) {
                    ulong fwspec_addr = read_pointer(dev_iommu_addr + field_offset(dev_iommu, fwspec), "iommu_fwspec");
                    uint ids = read_uint(fwspec_addr + field_offset(iommu_fwspec, ids), "ids");
                    sid = ids & 0xffff;
                }
                PRINT("         SID:%#-8x device:%#lx[%s] \n", sid, dev_addr, name.c_str());
            }
            PRINT("\n");
        }

        PRINT("\n");
    }
}

/**
 * Initialize kernel structure field offsets
 */
void IOMMU::init_offset(void) {
    field_init(page, lru);
    // Device structure fields
    field_init(device, iommu_group);
    field_init(device, iommu);
    field_init(device, driver_data);

    // IOMMU group structure fields
    field_init(iommu_group, domain);
    field_init(iommu_group, id);
    field_init(iommu_group, devices);
    field_init(iommu_group, default_domain);

    // Group device structure fields
    field_init(group_device, list);
    field_init(group_device, name);
    field_init(group_device, dev);

    // Per-device IOMMU structure fields
    field_init(dev_iommu, iommu_dev);
    field_init(dev_iommu, fwspec);
    field_init(iommu_fwspec, ids);

    // IOMMU device structure fields
    field_init(iommu_device, dev);

    // ARM SMMU device structure fields
    field_init(arm_smmu_device, dev);
    field_init(arm_smmu_device, base);
    field_init(arm_smmu_device, ioaddr);
    field_init(arm_smmu_device, numpage);
    field_init(arm_smmu_device, pgshift);
    field_init(arm_smmu_device, features);
    field_init(arm_smmu_device, options);
    field_init(arm_smmu_device, version);
    field_init(arm_smmu_device, model);
    field_init(arm_smmu_device, num_context_banks);
    field_init(arm_smmu_device, num_s2_context_banks);
    field_init(arm_smmu_device, va_size);
    field_init(arm_smmu_device, ipa_size);
    field_init(arm_smmu_device, pa_size);
    field_init(arm_smmu_device, cbs);

    // ARM SMMU domain structure fields
    field_init(arm_smmu_domain, domain);
    field_init(arm_smmu_domain, smmu);
    field_init(arm_smmu_domain, cfg);
    field_init(arm_smmu_domain, stage);
    field_init(arm_smmu_domain, secure_vmid);
    field_init(arm_smmu_domain, skip_tlb_management);
    field_init(arm_smmu_domain, freelist);
    field_init(arm_smmu_domain, pgtbl_ops);

    // IOMMU domain structure fields
    field_init(iommu_domain, type);
    field_init(iommu_domain, ops);
    field_init(iommu_domain, pgsize_bitmap);
    field_init(iommu_domain, geometry);
    field_init(iommu_domain, iova_cookie);
    field_init(iommu_domain, iopf_handler);
    field_init(iommu_domain, fault_data);

    // IOMMU domain geometry structure fields
    field_init(iommu_domain_geometry, aperture_start);
    field_init(iommu_domain_geometry, aperture_end);
    field_init(iommu_domain_geometry, force_aperture);

    // ARM SMMU context bank structure fields
    field_init(arm_smmu_cb, ttbr);
    field_init(arm_smmu_cb, tcr);
    field_init(arm_smmu_cb, mair);
    field_init(arm_smmu_cb, sctlr);
    field_init(arm_smmu_cb, cfg);

    // ARM SMMU configuration structure fields
    field_init(arm_smmu_cfg, cbndx);
    field_init(arm_smmu_cfg, irptndx);
    field_init(arm_smmu_cfg, asid);
    field_init(arm_smmu_cfg, vmid);
    field_init(arm_smmu_cfg, procid);
    field_init(arm_smmu_cfg, sctlr);
    field_init(arm_smmu_cfg, cbar);
    field_init(arm_smmu_cfg, fmt);

    field_init(dma_buf, attachments);
    field_init(dma_buf_attachment, node);
    field_init(dma_buf_attachment, dev);
}

/**
 * Initialize command help and usage information
 */
void IOMMU::init_command(void) {
    cmd_name = "iommu";
    help_str_list = {
        "iommu",
        "display IOMMU (Input-Output Memory Management Unit) information",
        "-l \n"
        "  iommu -g \n"
        "  This command displays IOMMU device and domain information.",
        "  Use -l to list all IOMMU devices.",
        "  Use -g to display IOMMU groups with associated devices.",
        "\n",
        "OPTIONS",
        "  -l",
        "    List all IOMMU devices in the system.",
        "",
        "  -g",
        "    Display all IOMMU groups with their associated devices.",
        "",
        "  -f",
        "    Display FastRPC channel and mapping information.",
        "",
        "  -k",
        "    Display KGSL driver and process information.",
        "\n",
        "EXAMPLES",
        "  List all IOMMU devices:",
        "    %s> iommu -l",
        "\n",
        "  Display IOMMU groups and device groups:",
        "    %s> iommu -g",
        "    [000] iommu_group:0xffffff8808a5b000",
        "        iommu_domain:0xffffff8808a5c000",
        "        arm_smmu_domain:0xffffff8808a5bf00",
        "        arm_smmu_device:0xffffff880a234000",
        "\n",
    };
}

/**
 * Default constructor
 */
IOMMU::IOMMU() {
    // Constructor body intentionally left empty
    // Initialization is handled by init_offset() and init_command()
}

#pragma GCC diagnostic pop
