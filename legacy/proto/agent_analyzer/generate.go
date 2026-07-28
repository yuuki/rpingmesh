//go:build ignore

// Package agent_analyzer provides protobuf definitions for Agent-Analyzer communication.
package agent_analyzer

//go:generate protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative agent_analyzer.proto
