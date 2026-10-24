/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/*
 * Minimal kernel type definitions for the uverbs tracer.
 *
 * The tracer deliberately avoids a generated vmlinux.h: it reads only the
 * user-space ABI of the uverbs character device (see uverbs_uapi.h), which
 * is stable by definition, plus two fields of core kernel structures that
 * every kernel with BTF describes (struct file and struct inode). Those two
 * are declared below with preserve_access_index so that CO-RE relocates
 * their field offsets against the running kernel's vmlinux BTF at load time.
 * Nothing here depends on the RDMA modules' BTF, which out-of-tree RDMA
 * stacks (OFED) do not ship.
 *
 * struct pt_regs is the kprobe context. Its layout is part of the kernel's
 * user-visible ABI (asm/ptrace.h), so it is declared verbatim per
 * architecture and accessed directly, without CO-RE.
 */
#ifndef __RPINGMESH_VMLINUX_MIN_H__
#define __RPINGMESH_VMLINUX_MIN_H__

/* Tells bpf_tracing.h to use the kernel's register names (di, si, ...). */
#define __VMLINUX_H__

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef signed long long __s64;
typedef signed int __s32;
typedef signed short __s16;
typedef signed char __s8;
typedef __u16 __be16;
typedef __u32 __be32;
typedef __u64 __be64;
typedef __u32 __wsum;
typedef __u8 u8;
typedef __u16 u16;
typedef __u32 u32;
typedef __u64 u64;
typedef _Bool bool;
#define true 1
#define false 0

/* The subset of include/uapi/linux/bpf.h the program uses. */
enum bpf_map_type {
	BPF_MAP_TYPE_HASH = 1,
	BPF_MAP_TYPE_ARRAY = 2,
	BPF_MAP_TYPE_RINGBUF = 27,
};

enum {
	BPF_ANY = 0,
};

#if defined(__TARGET_ARCH_x86)
/* arch/x86/include/asm/ptrace.h, 64-bit. */
struct pt_regs {
	unsigned long r15;
	unsigned long r14;
	unsigned long r13;
	unsigned long r12;
	unsigned long bp;
	unsigned long bx;
	unsigned long r11;
	unsigned long r10;
	unsigned long r9;
	unsigned long r8;
	unsigned long ax;
	unsigned long cx;
	unsigned long dx;
	unsigned long si;
	unsigned long di;
	unsigned long orig_ax;
	unsigned long ip;
	unsigned long cs;
	unsigned long flags;
	unsigned long sp;
	unsigned long ss;
};
#elif defined(__TARGET_ARCH_arm64)
/* arch/arm64/include/uapi/asm/ptrace.h; pt_regs starts with user_pt_regs,
 * which is what bpf_tracing.h reads the arguments from on arm64. */
struct user_pt_regs {
	__u64 regs[31];
	__u64 sp;
	__u64 pc;
	__u64 pstate;
};

struct pt_regs {
	struct user_pt_regs user_regs;
};
#else
#error "unsupported target architecture: build with bpf2go -target amd64 or arm64"
#endif

/* CO-RE: the fields below are relocated against the running kernel. */
struct inode {
	__u32 i_rdev;
} __attribute__((preserve_access_index));

struct file {
	struct inode *f_inode;
} __attribute__((preserve_access_index));

#endif /* __RPINGMESH_VMLINUX_MIN_H__ */
