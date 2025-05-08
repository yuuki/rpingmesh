package agent

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/yuuki/rpingmesh/pkg/ebpf"
)

// ServiceTracingManager manages the Service Tracing functionality for the Agent
type ServiceTracingManager struct {
	tracer      *ebpf.ServiceTracer
	connections map[string]ebpf.RdmaConnTuple
	rwMutex     sync.RWMutex
	tracingCh   chan ebpf.RdmaConnTuple
	ctx         context.Context
	cancel      context.CancelFunc

	// Callback functions for starting/stopping probes
	onNewConnection     func(conn ebpf.RdmaConnTuple)
	onRemovedConnection func(conn ebpf.RdmaConnTuple)
}

// NewServiceTracingManager creates a new ServiceTracingManager instance
func NewServiceTracingManager(
	onNewConnection func(conn ebpf.RdmaConnTuple),
	onRemovedConnection func(conn ebpf.RdmaConnTuple),
) (*ServiceTracingManager, error) {
	tracer, err := ebpf.NewServiceTracer()
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &ServiceTracingManager{
		tracer:              tracer,
		connections:         make(map[string]ebpf.RdmaConnTuple),
		tracingCh:           make(chan ebpf.RdmaConnTuple, 100),
		ctx:                 ctx,
		cancel:              cancel,
		onNewConnection:     onNewConnection,
		onRemovedConnection: onRemovedConnection,
	}, nil
}

// Start begins Service Tracing
func (m *ServiceTracingManager) Start() error {
	if err := m.tracer.Start(); err != nil {
		return err
	}

	// Start event processing in background
	go m.processEvents()

	log.Println("Service Tracing started")
	return nil
}

// Stop terminates Service Tracing
func (m *ServiceTracingManager) Stop() error {
	m.cancel()
	return m.tracer.Stop()
}

// GetConnections returns a list of currently tracked RDMA connections
func (m *ServiceTracingManager) GetConnections() []ebpf.RdmaConnTuple {
	m.rwMutex.RLock()
	defer m.rwMutex.RUnlock()

	connections := make([]ebpf.RdmaConnTuple, 0, len(m.connections))
	for _, conn := range m.connections {
		connections = append(connections, conn)
	}

	return connections
}

// processEvents processes events from eBPF
func (m *ServiceTracingManager) processEvents() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case event := <-m.tracer.Events():
			m.handleEvent(event)

		case <-ticker.C:
			// Periodic status log
			m.rwMutex.RLock()
			log.Printf("Currently tracking %d RDMA connections", len(m.connections))
			m.rwMutex.RUnlock()

		case <-m.ctx.Done():
			log.Println("Terminating Service Tracing processing")
			return
		}
	}
}

// handleEvent processes detected RDMA events
func (m *ServiceTracingManager) handleEvent(event ebpf.RdmaConnTuple) {
	m.rwMutex.Lock()
	defer m.rwMutex.Unlock()

	// Process based on event type
	switch event.EventType {
	case 2: // MODIFY
		// Track connection when state changes to RTR or RTS
		if event.QPState == 3 || event.QPState == 4 { // IB_QPS_RTR or IB_QPS_RTS
			key := m.connectionKey(event)

			// For new connections
			if _, exists := m.connections[key]; !exists {
				m.connections[key] = event
				log.Printf("New RDMA connection detected: %s", key)

				// Call callback function
				if m.onNewConnection != nil {
					go m.onNewConnection(event)
				}
			}
		}

	case 3: // DESTROY
		// Detect connection termination
		for key, conn := range m.connections {
			if conn.SrcQPN == event.SrcQPN {
				delete(m.connections, key)
				log.Printf("RDMA connection terminated: %s", key)

				// Call callback function
				if m.onRemovedConnection != nil {
					go m.onRemovedConnection(conn)
				}
			}
		}
	}
}

// connectionKey generates a unique key to identify a connection
func (m *ServiceTracingManager) connectionKey(conn ebpf.RdmaConnTuple) string {
	return conn.SrcGIDString() + ":" + string(conn.SrcQPN) + "-" +
		conn.DstGIDString() + ":" + string(conn.DstQPN)
}
