// Copyright (c) 2024 Qualcomm Innovation Center, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Clear

#ifndef STRUCT_DEFS_H_
#define STRUCT_DEFS_H_

extern "C" {
    #include "defs.h"
}
#include <iostream>
#include <string>
#include <linux/types.h>
#include <unistd.h>
#include <getopt.h>

#define TO_STRING(x) #x
#define TO_STD_STRING(x) std::string(TO_STRING(x))
#define TO_CONST_STRING(x) const_cast<char*>(x)

class Typeinfo {
public:
    std::string m_name;
    int m_size;
    int m_offset;

    Typeinfo(const std::string& type, const std::string& field)
        : m_name(type + "_" + field),
          m_size(datatype_info(TO_CONST_STRING(type.c_str()), TO_CONST_STRING(field.c_str()), MEMBER_SIZE_REQUEST)),
          m_offset(datatype_info(TO_CONST_STRING(type.c_str()), TO_CONST_STRING(field.c_str()), NULL)) {}

    Typeinfo(const std::string& type)
        : m_name(type),
          m_size(datatype_info(TO_CONST_STRING(type.c_str()), NULL, STRUCT_SIZE_REQUEST)),
          m_offset(0) {}

    int offset() const {
        return m_offset;
    }

    int size() const {
        return m_size;
    }
};

#endif // STRUCT_DEFS_H_
