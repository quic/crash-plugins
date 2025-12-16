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

#ifndef IOMMU_DEFS_H_
#define IOMMU_DEFS_H_

#include "plugin.h"

struct GroupInfo {
    int group_id;
    ulong iommu_domain_addr;
    ulong iommu_group_addr;
    ulong arm_smmu_device_addr;
    std::vector<ulong> devices;
};

class IOMMU : public ParserPlugin {
private:
    // Private members for internal state management
    std::set<ulong> domain_list;
    std::vector<GroupInfo> group_list;
    std::set<ulong> arm_smmu_device_list;

    // Helper functions for code reuse
    std::string get_device_name(ulong dev_addr);
    std::string get_enum_name(const std::map<std::string, ulong>& enum_list, ulong value);
    void print_arm_smmu_cfg(ulong cfg_addr, const std::map<std::string, ulong>& cbar_enum_list,
                            const std::map<std::string, ulong>& fmt_enum_list);
    void print_context_bank(ulong cb_addr, uint index, const std::map<std::string, ulong>& cbar_enum_list,
                           const std::map<std::string, ulong>& fmt_enum_list);

public:
    /**
     * Default constructor
     */
    IOMMU();

    /**
     * Main command entry point
     */
    void cmd_main(void) override;

    /**
     * Initialize kernel structure field offsets
     */
    void init_offset(void) override;

    /**
     * Initialize command help and usage information
     */
    void init_command(void) override;

    /**
     * Print detailed information about an ARM SMMU device
     */
    void print_arm_smmu_device(ulong arm_smmu_device_addr);

    /**
     * Print all IOMMU devices in the system
     */
    void print_iommu_devices(void);

    /**
     * Parse IOMMU domains from device tree
     */
    void parser_iommu_domains(void);

    /**
     * Print IOMMU groups with hierarchy
     */
    void print_iommu_groups(void);

    /**
     * Convert IOMMU domain type to string representation
     */
    const char* domain_type_to_string(uint type);

    /**
     * Print detailed information about an IOMMU domain
     */
    void print_iommu_domain_info(ulong domain_addr);

    // Plugin instance definition macro
    DEFINE_PLUGIN_INSTANCE(IOMMU)
};

#endif // IOMMU_DEFS_H_
