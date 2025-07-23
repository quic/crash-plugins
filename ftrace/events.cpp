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

#include "events.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpointer-arith"

void dwc3_ep_queue_event::handle(ulong addr,std::ostringstream& oss){
    print_dwc3_ep_status(addr,oss);
}

void dwc3_ep_dequeue_event::handle(ulong addr,std::ostringstream& oss){
    print_dwc3_ep_status(addr,oss);
}

void dwc3_prepare_trb_event::handle(ulong addr,std::ostringstream& oss){
    print_dwc3_trb_event(addr,oss);
}

void dwc3_gadget_giveback_event::handle(ulong addr,std::ostringstream& oss){
    print_dwc3_ep_status(addr,oss);
}

void dwc3_complete_trb_event::handle(ulong addr,std::ostringstream& oss){
    print_dwc3_trb_event(addr,oss);
}

void dwc3_event_event::handle(ulong addr,std::ostringstream& oss){
    oss << std::left << "event (";
    print_trace_field(addr, oss,"event");
    oss << std::left << ") ep0state:";
    print_trace_field(addr, oss,"ep0state");
}

void dwc3_gadget_ep_cmd_event::handle(ulong addr,std::ostringstream& oss){
    print_trace_field(addr, oss,"name");
    oss << std::left << ": cmd ";
    print_trace_field(addr, oss,"cmd");
    oss << std::left << "params ";
    print_trace_field(addr, oss,"param0");
    print_trace_field(addr, oss,"param1");
    print_trace_field(addr, oss,"param2");
    oss << std::left << "--> status: ";
    print_trace_field(addr, oss,"cmd_status");
}

// struct bprint_entry
void bprint_event::handle(ulong addr,std::ostringstream& oss){
    print_ip(addr,oss);
    print_trace_field(addr, oss,"buf");
}

// struct print_entry
void print_event::handle(ulong addr,std::ostringstream& oss){
    print_ip(addr,oss);
    print_trace_field(addr, oss,"buf");
}

// struct bputs_entry
void bputs_event::handle(ulong addr,std::ostringstream& oss){
    print_ip(addr,oss);
    print_trace_field(addr, oss,"str");
}

void kernel_stack_event::handle(ulong addr,std::ostringstream& oss){
    oss << std::left << "skipped kernel_stack_event";
}

void user_stack_event::handle(ulong addr,std::ostringstream& oss){
    oss << std::left << "skipped user_stack_event";
}

void binder_return_event::handle(ulong addr,std::ostringstream& oss){
    oss << std::left << "cmd=";
    print_trace_field(addr, oss,"cmd");
}

void binder_command_event::handle(ulong addr,std::ostringstream& oss){
    oss << std::left << "cmd=";
    print_trace_field(addr, oss,"cmd");
}

void softirq_entry_event::handle(ulong addr,std::ostringstream& oss){
    print_softirq(addr,oss);
}

void softirq_exit_event::handle(ulong addr,std::ostringstream& oss){
    print_softirq(addr,oss);
}

void softirq_raise_event::handle(ulong addr,std::ostringstream& oss){
    print_softirq(addr,oss);
}

void sched_switch_event::handle(ulong addr,std::ostringstream& oss){
    oss << std::left << "prev_comm=";
    print_trace_field(addr, oss,"prev_comm");
    oss << std::left << " prev_pid=";
    print_trace_field(addr, oss,"prev_pid");
    oss << std::left << " prev_prio=";
    print_trace_field(addr, oss,"prev_prio");
    oss << std::left << " prev_state=";
    std::shared_ptr<trace_field> filed_ptr = field_maps["prev_state"];
    long prev_state = plugin_ptr->read_long(addr + filed_ptr->offset,"prev_state");
    uint16_t mask = (((0x0000 | 0x0001 | 0x0002 | 0x0004 | 0x0008 | 0x0010 | 0x0020 | 0x0040) + 1) << 1) - 1;
    std::string state_str;
    switch (prev_state & mask) {
        case 0:
            state_str = "R";
            break;
        case 1:
            state_str = "S";
            break;
        case 2:
            state_str = "D";
            break;
        case 4:
            state_str = "T";
            break;
        case 8:
            state_str = "t";
            break;
        case 16:
            state_str = "X";
            break;
        case 32:
            state_str = "Z";
            break;
        case 64:
            state_str = "P";
            break;
        case 128:
            state_str = "I";
            break;
        default:
            state_str = "Unknown";
            break;
    }
    oss << std::left << state_str;
    oss << std::left << " ==> next_comm=";
    print_trace_field(addr, oss,"next_comm");
    oss << std::left << " next_pid=";
    print_trace_field(addr, oss,"next_pid");
    oss << std::left << " next_prio=";
    print_trace_field(addr, oss,"next_prio");
}

void irq_handler_exit_event::handle(ulong addr,std::ostringstream& oss){
    oss << std::left << "irq=";
    print_trace_field(addr, oss,"irq");
    std::shared_ptr<trace_field> filed_ptr = field_maps["ret"];
    oss << std::left << " ret=";
    int ret = plugin_ptr->read_int(addr + filed_ptr->offset,"ret");
    if (ret){
        oss << std::left << "handled";
    }else{
        oss << std::left << "unhandled";
    }
}
#pragma GCC diagnostic pop
