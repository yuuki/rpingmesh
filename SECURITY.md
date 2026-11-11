# Security policy

R-Pingmesh runs on the hosts and the network it monitors. The agent opens
RDMA devices with `CAP_IPC_LOCK` and membership in the `rdma` group, and,
when service tracing is enabled, loads eBPF programs with `CAP_BPF` and
`CAP_PERFMON` and reads `/proc`, sysfs and RDMA netlink dumps. It answers
probes from any host that can reach its UD queue pair. The controller stores
what agents register in rqlite or PostgreSQL and serves pinglists over gRPC; with
`tls_mode: disabled` or `tls` it cannot tell agents apart. The
[Configuration](README.md#configuration) section of the README describes TLS,
mTLS and the bounds the controller applies to unauthenticated requests;
running without `mtls` as documented there is not a vulnerability.

Examples of what is in scope: an agent or controller that crashes, hangs or
uses unbounded memory on crafted probe packets, gRPC requests, rqlite or
PostgreSQL responses, lldpcli output or kernel dumps; a privilege the agent's systemd
units grant beyond what the README documents; eBPF programs that read or
expose more than the queue-pair metadata they are meant to; TLS
configurations that are accepted but do not verify what they claim to.

## Supported versions

Security fixes are made on the `main` branch and released in the next
version. Only the latest release is supported. The archived implementation
under `legacy/` is not supported.

## Reporting a vulnerability

Please do **not** open a public issue, pull request or discussion.

Report the vulnerability privately with GitHub's
[private vulnerability reporting](https://github.com/yuuki/rpingmesh/security/advisories/new)
(the "Report a vulnerability" button of the Security tab). If that is not
possible, contact the author privately via the contact information on
https://github.com/yuuki.

Please include the version (`rpingmesh-agent --version` or
`rpingmesh-controller --version`), the relevant configuration (with secrets
removed), the kernel and RDMA stack (driver, `rdma-core` version), what an
attacker controls (a host on the RDMA fabric, a gRPC client, the rqlite
node or PostgreSQL server, a local process, ...), and the impact. You should receive an answer
within a few weeks; R-Pingmesh is maintained on a best-effort basis.
