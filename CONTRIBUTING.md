# Contributing

Thanks for your interest in R-Pingmesh. Bug reports, questions and pull
requests are welcome.

- **Bugs and ideas:** open an issue with the version, the configuration
  (without secrets or real host names), the RDMA stack and what you
  observed. Report security issues privately instead; see
  [SECURITY.md](SECURITY.md).
- **Pull requests:** keep each PR focused, explain what it changes and why,
  and list the commands you ran. Larger changes (new probe types, wire format,
  gRPC API, metrics) are best discussed in an issue first.

## Before you open a pull request

```sh
make check   # lint, workflow audit, race-enabled unit tests, Zig and script tests
```

`make check` needs Linux with Go, Zig 0.17.0, protoc, libibverbs-dev and
librdmacm-dev; [AGENTS.md](AGENTS.md) lists the extra checks for changes to
the eBPF programs, the Zig library or the protobuf API.

- Add or update tests for behaviour changes, and update README.md and
  CHANGELOG.md when users would notice the change.
- Call out changes to the wire format, C ABI, gRPC API, metric names or
  attributes, and configuration keys, and any new privileges or kernel
  requirements.
- Code comments and documentation are in English. Do not include real
  environment identifiers (host names, IP addresses, cluster names, paths).
- `legacy/` is archived; changes there are accepted only for legacy
  maintenance.

## Commit messages

Commits, branches and pull request titles follow the Git conventions in
[AGENTS.md](AGENTS.md#git-conventions).
