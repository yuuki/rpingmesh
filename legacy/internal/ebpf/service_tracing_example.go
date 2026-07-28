package ebpf

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// ExampleServiceTracing demonstrates how to use Service Tracing
func ExampleServiceTracing() {
	// Initialize ServiceTracer
	tracer, err := NewServiceTracer()
	if err != nil {
		log.Fatalf("failed to initialize service tracer: %v", err)
	}
	defer tracer.Stop()

	// Start tracing
	if err := tracer.Start(); err != nil {
		log.Fatalf("failed to start tracing: %v", err)
	}
	log.Println("Started RDMA service tracing...")

	// Setup signal handling
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigCh
		log.Println("Received termination signal. Stopping tracing...")
		cancel()
	}()

	// Temporary map to store RDMA connection 5-tuple information for ServiceProber
	rdmaConnections := make(map[string]RdmaConnTuple)

	// Event processing loop
	for {
		select {
		case event := <-tracer.Events():
			// Process event
			log.Println("RDMA event detected:", event.String())

			// For MODIFY events, store 5-tuple information
			if event.EventType == 2 && event.QPState == 3 { // IB_QPS_RTR state
				key := fmt.Sprintf("%s:%d-%s:%d",
					event.SrcGIDString(), event.SrcQPN,
					event.DstGIDString(), event.DstQPN)

				rdmaConnections[key] = event
				log.Printf("Active RDMA connection detected: %s", key)

				// Pass 5-tuple information to ServiceProber for actual probing
				// Example: serviceProber.StartProbing(event.SrcGID, event.SrcQPN, event.DstGID, event.DstQPN)
			}

			// For DESTROY events, remove from known connections
			if event.EventType == 3 {
				for key, conn := range rdmaConnections {
					if conn.SrcQPN == event.SrcQPN {
						delete(rdmaConnections, key)
						log.Printf("RDMA connection removed: %s", key)

						// Stop probing for this connection
						// Example: serviceProber.StopProbing(conn.SrcGID, conn.SrcQPN, conn.DstGID, conn.DstQPN)
					}
				}
			}

		case <-ctx.Done():
			// Terminate
			log.Println("Terminating tracing")
			return

		case <-time.After(60 * time.Second):
			// Periodic status update (optional)
			log.Printf("Currently tracking %d RDMA connections", len(rdmaConnections))
		}
	}
}
