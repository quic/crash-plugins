// Copyright (c) 2024-2025 Qualcomm Innovation Center, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Clear

#include "logger/log.h"

Logger gLog(Logger::LEVEL_ERROR);
Logger* Logger::INSTANCE = &gLog;
