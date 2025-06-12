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

#ifndef BOOT_DEFS_H_
#define BOOT_DEFS_H_

#include "plugin.h"

struct pmic_event_t {
    uint8_t state;
    uint8_t event;
    uint8_t data1;
    uint8_t data0;
};

enum pmic_pon_event {
	PMIC_PON_EVENT_PON_TRIGGER_RECEIVED	= 0x01,
	PMIC_PON_EVENT_OTP_COPY_COMPLETE	= 0x02,
	PMIC_PON_EVENT_TRIM_COMPLETE		= 0x03,
	PMIC_PON_EVENT_XVLO_CHECK_COMPLETE	= 0x04,
	PMIC_PON_EVENT_PMIC_CHECK_COMPLETE	= 0x05,
	PMIC_PON_EVENT_RESET_TRIGGER_RECEIVED	= 0x06,
	PMIC_PON_EVENT_RESET_TYPE		= 0x07,
	PMIC_PON_EVENT_WARM_RESET_COUNT		= 0x08,
	PMIC_PON_EVENT_FAULT_REASON_1_2		= 0x09,
	PMIC_PON_EVENT_FAULT_REASON_3		= 0x0A,
	PMIC_PON_EVENT_PBS_PC_DURING_FAULT	= 0x0B,
	PMIC_PON_EVENT_FUNDAMENTAL_RESET	= 0x0C,
	PMIC_PON_EVENT_PON_SEQ_START		= 0x0D,
	PMIC_PON_EVENT_PON_SUCCESS		= 0x0E,
	PMIC_PON_EVENT_WAITING_ON_PSHOLD	= 0x0F,
	PMIC_PON_EVENT_PMIC_SID1_FAULT		= 0x10,
	PMIC_PON_EVENT_PMIC_SID2_FAULT		= 0x11,
	PMIC_PON_EVENT_PMIC_SID3_FAULT		= 0x12,
	PMIC_PON_EVENT_PMIC_SID4_FAULT		= 0x13,
	PMIC_PON_EVENT_PMIC_SID5_FAULT		= 0x14,
	PMIC_PON_EVENT_PMIC_SID6_FAULT		= 0x15,
	PMIC_PON_EVENT_PMIC_SID7_FAULT		= 0x16,
	PMIC_PON_EVENT_PMIC_SID8_FAULT		= 0x17,
	PMIC_PON_EVENT_PMIC_SID9_FAULT		= 0x18,
	PMIC_PON_EVENT_PMIC_SID10_FAULT		= 0x19,
	PMIC_PON_EVENT_PMIC_SID11_FAULT		= 0x1A,
	PMIC_PON_EVENT_PMIC_SID12_FAULT		= 0x1B,
	PMIC_PON_EVENT_PMIC_SID13_FAULT		= 0x1C,
	PMIC_PON_EVENT_PMIC_VREG_READY_CHECK	= 0x20,
};

enum pmic_pon_reset_type {
	PMIC_PON_RESET_TYPE_WARM_RESET		= 0x1,
	PMIC_PON_RESET_TYPE_SHUTDOWN		= 0x4,
	PMIC_PON_RESET_TYPE_HARD_RESET		= 0x7,
};

class BootInfo : public ParserPlugin {
private:
    std::unordered_map<uint32_t, std::string> pmic_pon_trigger_map;
    std::unordered_map<uint32_t, std::string> pmic_pon_reset_trigger_map;
    std::vector<std::string> pmic_pon_fault_reason1;
    std::vector<std::string> pmic_pon_fault_reason2;
    std::vector<std::string> pmic_pon_fault_reason3;

    std::vector<std::string> pmic_pon_s3_reset_reason;
    std::vector<std::string> pmic_pon_pon_pbl_status;
	std::vector<std::string> pmic_pon_reset_type_label;

public:
    BootInfo();
    void read_pmic_pon_trigger_maps();
    void pmic_pon_log_print_reason(uint8_t data, std::vector<std::string> reasons);
    void parser_pmic_pon_log_dev(ulong addr);
    void print_pmic_info();
    void print_boot_log();
    std::string remove_invalid_chars(const std::string& msg);
    void cmd_main(void) override;
    DEFINE_PLUGIN_INSTANCE(BootInfo)
};

#endif // BOOT_DEFS_H_
