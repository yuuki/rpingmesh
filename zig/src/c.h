// c.h - C headers translated into the `c` Zig module by build.zig.
//
// Zig 0.16+ removed the @cImport builtin; C bindings are now produced by the
// build system's TranslateC step and imported as a module. types.zig
// re-exports the result as `types.c`.

#include <infiniband/verbs.h>
#include <rdma/rdma_cma.h>
#include <fcntl.h>
#include <time.h>
#include <unistd.h>
