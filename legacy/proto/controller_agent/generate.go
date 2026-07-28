//go:build ignore

// Package controller_agent provides protobuf definitions for Controller-Agent communication.
package controller_agent

//go:generate protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative controller_agent.proto
