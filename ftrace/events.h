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

#ifndef EVENTS_DEFS_H_
#define EVENTS_DEFS_H_

#include "trace_event.h"
#define DEFINE_EVENT(name)                                      \
class name##_event : public TraceEvent {                        \
    public:                                                     \
    void handle(ulong addr,std::ostringstream& oss) override;   \
};

DEFINE_EVENT(bprint)
DEFINE_EVENT(print)
DEFINE_EVENT(kernel_stack)
DEFINE_EVENT(user_stack)
DEFINE_EVENT(bputs)
DEFINE_EVENT(sched_switch)
DEFINE_EVENT(softirq_raise)
DEFINE_EVENT(softirq_entry)
DEFINE_EVENT(softirq_exit)
DEFINE_EVENT(irq_handler_exit)
DEFINE_EVENT(binder_return)
DEFINE_EVENT(binder_command)
DEFINE_EVENT(dwc3_ep_queue)
DEFINE_EVENT(dwc3_ep_dequeue)
DEFINE_EVENT(dwc3_prepare_trb)
DEFINE_EVENT(dwc3_gadget_giveback)
DEFINE_EVENT(dwc3_gadget_ep_cmd)
DEFINE_EVENT(dwc3_event)
DEFINE_EVENT(dwc3_complete_trb)
DEFINE_EVENT(rwmmio_read)
DEFINE_EVENT(rwmmio_write)
DEFINE_EVENT(rwmmio_post_read)
DEFINE_EVENT(rwmmio_post_write)
DEFINE_EVENT(gpio_value)
DEFINE_EVENT(gpio_direction)
#endif // EVENTS_DEFS_H_