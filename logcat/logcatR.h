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

#ifndef LOGCAT_R_DEFS_H_
#define LOGCAT_R_DEFS_H_

#include "logcat.h"

struct __attribute__((__packed__)) LogBufferElement {
    const uint32_t mUid;
    const uint32_t mPid;
    const uint32_t mTid;
    struct log_time mRealTime;
    union {
        char *mMsg;
        int32_t mTag;
    };
    union {
        const uint16_t mMsgLen;
        uint16_t mDroppedCount;
    };
    const uint8_t mLogId;
    uint8_t mDropped;
};

class LogcatR : public Logcat {
private:
    ulong parser_logbuf_addr() override;
    void parser_LogBufferElement(ulong vaddr);

public:
    LogcatR(std::shared_ptr<Swapinfo> swap);
    void parser_logbuf(ulong buf_addr) override;
    size_t get_logbuf_addr_from_bss() override;
};

#endif // LOGCAT_R_DEFS_H_