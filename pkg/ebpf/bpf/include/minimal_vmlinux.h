// Minimal vmlinux.h for eBPF compilation
// This is used when BTF information is not available from the kernel

#ifndef __VMLINUX_H__
#define __VMLINUX_H__

// Include standard types first, let the compiler find the correct ones
#include <linux/types.h>

// Define only what's absolutely necessary and not provided by standard headers

// IB QP states used in our tracing
// These values are standard IB verbs definitions
#define IB_QPS_RESET                0
#define IB_QPS_INIT                 1
#define IB_QPS_RTR                  2
#define IB_QPS_RTS                  3
#define IB_QPS_SQD                  4
#define IB_QPS_SQE                  5
#define IB_QPS_ERR                  6

// Event types for our custom ring buffer
#define RDMA_EVENT_CREATE_QP        1
#define RDMA_EVENT_MODIFY_QP        2
#define RDMA_EVENT_DESTROY_QP       3

#endif /* __VMLINUX_H__ */
