// Minimal vmlinux.h for eBPF compilation
// This is used when BTF information is not available from the kernel

#pragma once

#define NULL ((void *)0)

typedef signed char __s8;

typedef unsigned char __u8;

typedef short int __s16;

typedef short unsigned int __u16;

typedef int __s32;

typedef unsigned int __u32;

typedef long long int __s64;

typedef long long unsigned int __u64;

typedef __s8 s8;

typedef __u8 u8;

typedef __s16 s16;

typedef __u16 u16;

typedef __s32 s32;

typedef __u32 u32;

typedef __s64 s64;

typedef __u64 u64;

enum {
    false = 0,
    true = 1,
};

#ifndef __custom_wsum_defined
#define __custom_wsum_defined
typedef __u32 __wsum;  // Define __wsum as __u32 as a placeholder. Actual type
                       // might be different.
#endif

#ifndef __custom_pt_regs_defined
#define __custom_pt_regs_defined
// Basic definition for struct pt_regs for eBPF kprobe usage
// The layout must match the specific architecture.
// This is a simplified version for x86_64 common registers.
// For full CO-RE, actual kernel BTF is best.
// Adjusted to use rdi, rsi, rdx etc. as expected by bpf_tracing.h macros for
// x86_64
struct pt_regs {
    unsigned long r15;
    unsigned long r14;
    unsigned long r13;
    unsigned long r12;
    unsigned long rbp;  // Commonly rbp for base pointer
    unsigned long rbx;  // Commonly rbx
    unsigned long r11;
    unsigned long r10;
    unsigned long r9;
    unsigned long r8;
    unsigned long rax;       // Commonly rax for accumulator
    unsigned long rcx;       // Commonly rcx for counter
    unsigned long rdx;       // Commonly rdx for data
    unsigned long rsi;       // Commonly rsi for source index
    unsigned long rdi;       // Commonly rdi for destination index
    unsigned long orig_rax;  // Original rax for syscalls
    unsigned long rip;       // Commonly rip for instruction pointer
    unsigned long cs;
    unsigned long eflags;  // Commonly eflags for flags
    unsigned long rsp;     // Commonly rsp for stack pointer
    unsigned long ss;
    // Add other registers if needed by specific kprobes or arch
};

enum bpf_map_type {
    BPF_MAP_TYPE_HASH = 1,
    BPF_MAP_TYPE_ARRAY = 2,
    BPF_MAP_TYPE_PROG_ARRAY = 3,
    BPF_MAP_TYPE_PERF_EVENT_ARRAY = 4,
    BPF_MAP_TYPE_PERCPU_HASH = 5,
    BPF_MAP_TYPE_PERCPU_ARRAY = 6,
    BPF_MAP_TYPE_STACK_TRACE = 7,
    BPF_MAP_TYPE_CGROUP_ARRAY = 8,
    BPF_MAP_TYPE_LRU_HASH = 9,
    BPF_MAP_TYPE_LRU_PERCPU_HASH = 10,
    BPF_MAP_TYPE_LPM_TRIE = 11,
    BPF_MAP_TYPE_ARRAY_OF_MAPS = 12,
    BPF_MAP_TYPE_HASH_OF_MAPS = 13,
    BPF_MAP_TYPE_DEVMAP = 14,
    BPF_MAP_TYPE_SOCKMAP = 15,
    BPF_MAP_TYPE_CPUMAP = 16,
    BPF_MAP_TYPE_XSKMAP = 17,
    BPF_MAP_TYPE_SOCKHASH = 18,
    BPF_MAP_TYPE_CGROUP_STORAGE_DEPRECATED = 19,
    BPF_MAP_TYPE_CGROUP_STORAGE = 19,
    BPF_MAP_TYPE_REUSEPORT_SOCKARRAY = 20,
    BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE_DEPRECATED = 21,
    BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE = 21,
    BPF_MAP_TYPE_QUEUE = 22,
    BPF_MAP_TYPE_STACK = 23,
    BPF_MAP_TYPE_SK_STORAGE = 24,
    BPF_MAP_TYPE_DEVMAP_HASH = 25,
    BPF_MAP_TYPE_STRUCT_OPS = 26,
    BPF_MAP_TYPE_RINGBUF = 27,
    BPF_MAP_TYPE_INODE_STORAGE = 28,
    BPF_MAP_TYPE_TASK_STORAGE = 29,
    BPF_MAP_TYPE_BLOOM_FILTER = 30,
    BPF_MAP_TYPE_USER_RINGBUF = 31,
    BPF_MAP_TYPE_CGRP_STORAGE = 32,
};

#endif
