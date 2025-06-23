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

#ifndef LOGCAT_LE_DEFS_H_
#define LOGCAT_LE_DEFS_H_

#include "logcat.h"

struct LogBufferElement_LE {
    //  virtual ~LogBufferElement();
    uint64_t mVptr;
    const uint32_t mLogId;
    const uint32_t mUid;
    const uint32_t mPid;
    const uint32_t mTid;
    char *mMsg;
    union {
        const unsigned short mMsgLen;
        unsigned short mDropped;
    };
    const uint64_t mSequence;
    struct log_time mRealTime;
};

class LogcatLE : public Logcat {
private:
    ulong parser_logbuf_addr() override;
    void parser_LogBufferElement(ulong vaddr);

public:
    LogcatLE(std::shared_ptr<Swapinfo> swap);
    void parser_logbuf(ulong buf_addr) override;
    size_t get_logbuf_addr_from_bss() override;
};

#endif // LOGCAT_LE_DEFS_H_