// Copyright (c) 2024 Qualcomm Innovation Center, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Clear

#ifndef BINDER_DEFS_H_
#define BINDER_DEFS_H_

#include "plugin.h"

class Binder : public PaserPlugin {
public:
    static const int BINDER_THREAD = 0x0001;
    static const int BINDER_NODE = 0x0002;
    static const int BINDER_REF = 0x0004;
    static const int BINDER_ALLOC = 0x0008;

    char* sched_name[7] = {
        TO_CONST_STRING("SCHED_NORMAL"),
        TO_CONST_STRING("SCHED_FIFO"),
        TO_CONST_STRING("SCHED_RR"),
        TO_CONST_STRING("SCHED_BATCH"),
        TO_CONST_STRING("SCHED_ISO"),
        TO_CONST_STRING("SCHED_IDLE"),
        TO_CONST_STRING("SCHED_DEADLINE"),
    };
    Binder();

    void cmd_main(void) override;
    void print_binder_transaction_log_entry(bool fail_log);
    void binder_proc_show(struct binder_argument_t* binder_arg);
    void print_binder_alloc(struct task_context *tc,ulong alloc_addr);
    void print_binder_proc(ulong proc_addr,int flags);
    void print_binder_node_nilocked(ulong node_addr);
    void print_binder_ref_olocked(ulong ref_addr);
    void print_binder_thread_ilocked(ulong thread);
    void print_binder_transaction_ilocked(ulong proc_addr, const char* prefix, ulong transaction);
    void print_binder_work_ilocked(ulong proc_addr, const char* prefix, const char* transaction_prefix, ulong work);
    char*convert_sched(int i);
    DEFINE_PLUGIN_INSTANCE(Binder)
};

struct binder_argument_t {
    struct task_context *tc;
    int pid;
    int dump_all;
    int flags;
};

struct hlist_head {
    struct kernel_list_head *first;
};

/**
 * union binder_priority - scheduler policy and priority
 * @sched_policy            scheduler policy
 * @prio                    [100..139] for SCHED_NORMAL, [0..99] for FIFO/RT
 *
 * The binder driver supports inheriting the following scheduler policies:
 * SCHED_NORMAL
 * SCHED_BATCH
 * SCHED_FIFO
 * SCHED_RR
 */
struct binder_priority {
	unsigned int sched_policy;
	int prio;
};

struct binder_buffer {
    struct kernel_list_head entry; /* free and allocated entries by address */
    struct rb_node rb_node; /* free entry by size or allocated entry */
    /* by address */
    unsigned free:1;
    unsigned clear_on_free:1;
    unsigned allow_user_free:1;
    unsigned async_transaction:1;
    unsigned oneway_spam_suspect:1;
    unsigned debug_id:27;
    void *transaction;
    void *target_node;
    size_t data_size;
    size_t offsets_size;
    size_t extra_buffers_size;
    void *user_data;
    int  pid;
};

/**
 * struct binder_work - work enqueued on a worklist
 * @entry:             node enqueued on list
 * @type:              type of work to be performed
 *
 * There are separate work lists for proc, thread, and node (async).
 */
enum binder_work_type {
    BINDER_WORK_TRANSACTION = 1,
    BINDER_WORK_TRANSACTION_COMPLETE,
    BINDER_WORK_TRANSACTION_PENDING,
    BINDER_WORK_TRANSACTION_ONEWAY_SPAM_SUSPECT,
    BINDER_WORK_RETURN_ERROR,
    BINDER_WORK_NODE,
    BINDER_WORK_DEAD_BINDER,
    BINDER_WORK_DEAD_BINDER_AND_CLEAR,
    BINDER_WORK_CLEAR_DEATH_NOTIFICATION,
};

struct binder_work {
    struct kernel_list_head entry;
    enum binder_work_type type;
};

struct binder_error {
    struct binder_work work;
    unsigned int cmd;
};

struct binder_ref_data {
	int debug_id;
	uint32_t desc;
	int strong;
	int weak;
};

struct binder_ref {
	struct binder_ref_data data;
	struct rb_node rb_node_desc;
	struct rb_node rb_node_node;
	struct kernel_list_head node_entry;
	void *proc;
	void *node;
	void *death;
};

#define BINDERFS_MAX_NAME 255

struct binder_transaction_log_entry {
	int debug_id;
	int debug_id_done;
	int call_type;
	int from_proc;
	int from_thread;
	int target_handle;
	int to_proc;
	int to_thread;
	int to_node;
	int data_size;
	int offsets_size;
	int return_error_line;
	uint32_t return_error;
	uint32_t return_error_param;
	char context_name[BINDERFS_MAX_NAME + 1];
};

struct binder_transaction_log {
	int cur;
	bool full;
	struct binder_transaction_log_entry entry[32];
};

struct binder_alloc {
	void *vma;
	void *vma_vm_mm;
	void *buffer;
	struct kernel_list_head buffers;
	struct rb_root free_buffers;
	struct rb_root allocated_buffers;
	uint32_t free_async_space;
	void *pages;
	uint32_t buffer_size;
	uint32_t buffer_free;
	int pid;
	uint32_t pages_high;
	bool oneway_spam_detected;
};

struct binder_lru_page {
	struct kernel_list_head lru;
	void *page_ptr;
	void *alloc;
};

struct binder_proc_part1 {
	struct kernel_list_head proc_node;
	struct rb_root threads;
	struct rb_root nodes;
	struct rb_root refs_by_desc;
	struct rb_root refs_by_node;
	struct kernel_list_head waiting_threads;
	int pid;
	void *tsk;
	void *cred;
	struct kernel_list_head deferred_work_node;
	int deferred_work;
	int outstanding_txns;
	bool is_dead;
	bool is_frozen;
	bool sync_recv;
	bool async_recv;
};

struct binder_proc_part2 {
	int max_threads;
	int requested_threads;
	int requested_threads_started;
	int tmp_ref;
	struct binder_priority default_priority;
};

struct binder_thread {
	void *proc;
	struct rb_node rb_node;
	struct kernel_list_head waiting_thread_node;
	int pid;
	int looper;              /* only modified by this thread */
	bool looper_need_return; /* can be written by other thread */
	void *transaction_stack;
	struct kernel_list_head todo;
	bool process_todo;
	struct binder_error return_error;
	struct binder_error reply_error;
};

struct binder_node {
	struct binder_work work;
	union {
		struct rb_node rb_node;
		struct kernel_list_head dead_node;
	};
	void *proc;
	struct hlist_head refs;
	int internal_strong_refs;
	int local_weak_refs;
	int local_strong_refs;
	int tmp_refs;
	unsigned long long ptr;
	unsigned long long cookie;
	struct {
		/*
		 * bitfield elements protected by
		 * proc inner_lock
		 */
		uint8_t has_strong_ref:1;
		uint8_t pending_strong_ref:1;
		uint8_t has_weak_ref:1;
		uint8_t pending_weak_ref:1;
	};
	struct {
		/*
		 * invariant after initialization
		 */
		uint8_t sched_policy:2;
		uint8_t inherit_rt:1;
		uint8_t accept_fds:1;
		uint8_t txn_security_ctx:1;
		uint8_t min_priority;
	};
	bool has_async_transaction;
	struct kernel_list_head async_todo;
};

#endif // BINDER_DEFS_H_
