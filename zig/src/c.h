// c.h - C headers translated into the `c` Zig module by build.zig.
//
// Zig 0.16+ removed the @cImport builtin; C bindings are now produced by the
// build system's TranslateC step and imported as a module. types.zig
// re-exports the result as `types.c`.

#include <infiniband/verbs.h>
#include <rdma/rdma_cma.h>
/* The C-ABI header shared with Go: its RDMA_* constants are the single
 * source of truth for the matching Zig constants and enum tags, and its
 * typedef structs are size-checked against the Zig extern structs. */
#include "rdma_bridge.h"
#include <fcntl.h>
#include <poll.h>
#include <sys/eventfd.h>
#include <time.h>
#include <unistd.h>
