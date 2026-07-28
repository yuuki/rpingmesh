//go:build ignore

// Package rpingmesh provides code generation directives for the entire project.
package main

// Generate protobuf code for all proto packages
//go:generate go generate ./proto/controller_agent
//go:generate go generate ./proto/agent_analyzer

// Generate eBPF code
//go:generate go generate ./internal/ebpf
