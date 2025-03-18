// Copyright (c) 2024-2025 Qualcomm Innovation Center, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Clear

#ifndef LOGCAT_R_DEFS_H_
#define LOGCAT_R_DEFS_H_

#include "logcat.h"

struct LogBufferElement {
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
    bool mDropped;
};

class LogcatR : public Logcat {
public:
    LogcatR(std::shared_ptr<Swapinfo> swap);
    ulong parser_logbuf_addr() override;
    void parser_logbuf(ulong buf_addr) override;
    void parser_LogBufferElement(ulong vaddr);
};

#endif // LOGCAT_R_DEFS_H_