package ebpf

import (
	"testing"
	"time"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRdmaConnTuple_EventTypeString(t *testing.T) {
	tests := []struct {
		name      string
		eventType uint8
		expected  string
	}{
		{"Create event", RdmaEventCreate, "CREATE"},
		{"Modify event", RdmaEventModify, "MODIFY"},
		{"Destroy event", RdmaEventDestroy, "DESTROY"},
		{"Unknown event", 99, "UNKNOWN"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tuple := &RdmaConnTuple{EventType: tt.eventType}
			assert.Equal(t, tt.expected, tuple.EventTypeString())
		})
	}
}

func TestRdmaConnTuple_IsValidEvent(t *testing.T) {
	tests := []struct {
		name      string
		eventType uint8
		expected  bool
	}{
		{"Valid create", RdmaEventCreate, true},
		{"Valid modify", RdmaEventModify, true},
		{"Valid destroy", RdmaEventDestroy, true},
		{"Invalid zero", 0, false},
		{"Invalid high", 99, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tuple := &RdmaConnTuple{EventType: tt.eventType}
			assert.Equal(t, tt.expected, tuple.IsValidEvent())
		})
	}
}

func TestRdmaConnTuple_SrcGIDString(t *testing.T) {
	tuple := &RdmaConnTuple{}
	// Set a test GID (fe80::1)
	copy(tuple.SrcGID[:], []byte{0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01})

	expected := "fe800000000000000000000000000001"
	assert.Equal(t, expected, tuple.SrcGIDString())
}

func TestRdmaConnTuple_DstGIDString(t *testing.T) {
	tuple := &RdmaConnTuple{}
	// Set a test GID (fe80::2)
	copy(tuple.DstGID[:], []byte{0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02})

	expected := "fe800000000000000000000000000002"
	assert.Equal(t, expected, tuple.DstGIDString())
}

func TestRdmaConnTuple_CommString(t *testing.T) {
	tuple := &RdmaConnTuple{}
	// Set a test process name with null termination
	copy(tuple.Comm[:], []byte("test_proc\x00\x00\x00\x00\x00\x00\x00"))

	expected := "test_proc"
	assert.Equal(t, expected, tuple.CommString())
}

func TestRdmaConnTuple_String(t *testing.T) {
	tuple := &RdmaConnTuple{
		Timestamp: uint64(time.Unix(1234567890, 0).UnixNano()),
		EventType: RdmaEventModify,
		SrcQPN:    1234,
		DstQPN:    5678,
		QPState:   3, // IB_QPS_RTR
		PID:       9999,
		PortNum:   1,
	}

	// Set test GIDs
	copy(tuple.SrcGID[:], []byte{0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01})
	copy(tuple.DstGID[:], []byte{0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02})
	copy(tuple.Comm[:], []byte("test_app\x00\x00\x00\x00\x00\x00\x00\x00"))

	result := tuple.String()

	// Check that all important fields are present in the string
	assert.Contains(t, result, "MODIFY")
	assert.Contains(t, result, "1234")                             // SrcQPN
	assert.Contains(t, result, "5678")                             // DstQPN
	assert.Contains(t, result, "fe800000000000000000000000000001") // SrcGID
	assert.Contains(t, result, "fe800000000000000000000000000002") // DstGID
	assert.Contains(t, result, "test_app")                         // Comm
}

func TestRdmaConnTuple_StructAlignment(t *testing.T) {
	// Test that the struct size is as expected for proper alignment
	tuple := &RdmaConnTuple{}

	// Expected size: 8 + 16 + 16 + 4 + 4 + 4 + 4 + 4 + 1 + 1 + 2 + 16 = 80 bytes
	expectedSize := 80
	actualSize := int(unsafe.Sizeof(*tuple))

	assert.Equal(t, expectedSize, actualSize,
		"Struct size mismatch - alignment may be incorrect")
}

// Mock test for ServiceTracer functionality (requires actual eBPF support to run)
func TestServiceTracer_NewServiceTracer(t *testing.T) {
	t.Skip("Skipping eBPF test - requires kernel support and privileges")

	// This test would require:
	// 1. Root privileges or CAP_BPF capability
	// 2. Kernel with eBPF support
	// 3. RDMA kernel modules loaded

	tracer, err := NewServiceTracer()
	require.NoError(t, err)
	require.NotNil(t, tracer)

	defer func() {
		if tracer != nil {
			tracer.Stop()
		}
	}()

	// Test that events channel is available
	assert.NotNil(t, tracer.Events())

	// Test statistics (should return empty initially)
	stats, err := tracer.GetStatistics()
	require.NoError(t, err)
	assert.Contains(t, stats, "create_count")
	assert.Contains(t, stats, "modify_count")
	assert.Contains(t, stats, "destroy_count")
	assert.Contains(t, stats, "error_count")
}

// Test constants match expected values
func TestConstants(t *testing.T) {
	assert.Equal(t, 1, RdmaEventCreate)
	assert.Equal(t, 2, RdmaEventModify)
	assert.Equal(t, 3, RdmaEventDestroy)

	assert.Equal(t, 0, StatCreateCount)
	assert.Equal(t, 1, StatModifyCount)
	assert.Equal(t, 2, StatDestroyCount)
	assert.Equal(t, 3, StatErrorCount)
	assert.Equal(t, 4, StatGidReadSuccess)
	assert.Equal(t, 5, StatGidReadFailure)
}

// Benchmark for GID string conversion
func BenchmarkRdmaConnTuple_SrcGIDString(b *testing.B) {
	tuple := &RdmaConnTuple{}
	copy(tuple.SrcGID[:], []byte{0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = tuple.SrcGIDString()
	}
}

// Benchmark for event validation
func BenchmarkRdmaConnTuple_IsValidEvent(b *testing.B) {
	tuple := &RdmaConnTuple{EventType: RdmaEventModify}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = tuple.IsValidEvent()
	}
}

// Test GID read failure diagnosis functions
func TestDiagnoseGidReadFailures(t *testing.T) {
	// Test with various statistics scenarios
	testCases := []struct {
		name  string
		stats map[string]uint64
	}{
		{
			name: "all_failures",
			stats: map[string]uint64{
				"gid_read_success": 0,
				"gid_read_failure": 10,
				"error_count":      5,
			},
		},
		{
			name: "mixed_results",
			stats: map[string]uint64{
				"gid_read_success": 5,
				"gid_read_failure": 3,
				"error_count":      2,
			},
		},
		{
			name: "all_success",
			stats: map[string]uint64{
				"gid_read_success": 10,
				"gid_read_failure": 0,
				"error_count":      0,
			},
		},
		{
			name: "no_activity",
			stats: map[string]uint64{
				"gid_read_success": 0,
				"gid_read_failure": 0,
				"error_count":      0,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// This function primarily logs, so we're just testing it doesn't panic
			assert.NotPanics(t, func() {
				DiagnoseGidReadFailures(tc.stats)
			})
		})
	}
}

// Test PrintBpfTraceLog function
func TestPrintBpfTraceLog(t *testing.T) {
	// This function primarily logs, so we're just testing it doesn't panic
	assert.NotPanics(t, func() {
		PrintBpfTraceLog()
	})
}
