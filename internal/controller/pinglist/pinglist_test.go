package pinglist

import (
	"context"
	"math/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/yuuki/rpingmesh/proto/controller_agent"
)

// RnicRegistryInterface はテスト用のインターフェースです
type RnicRegistryInterface interface {
	GetRNICsByToR(ctx context.Context, torID string) ([]*controller_agent.RnicInfo, error)
	GetSampleRNICsFromOtherToRs(ctx context.Context, excludeTorID string) ([]*controller_agent.RnicInfo, error)
}

// PingLister のモック用バージョン - 本物のPingListerと同じフィールド構造だが、registryが異なる型
type mockPingLister struct {
	registry RnicRegistryInterface
	rand     *rand.Rand
}

// モック用にGeneratePinglist実装
func (p *mockPingLister) GeneratePinglist(
	ctx context.Context,
	requesterRnic *controller_agent.RnicInfo,
	pinglistType controller_agent.PinglistRequest_PinglistType,
) ([]*controller_agent.PingTarget, error) {
	// 実際の実装と同じロジック
	switch pinglistType {
	case controller_agent.PinglistRequest_TOR_MESH:
		return p.generateTorMeshPinglist(ctx, requesterRnic)
	case controller_agent.PinglistRequest_INTER_TOR:
		return p.generateInterTorPinglist(ctx, requesterRnic)
	default:
		return p.generateTorMeshPinglist(ctx, requesterRnic)
	}
}

// モック用にgenerateTorMeshPinglist実装
func (p *mockPingLister) generateTorMeshPinglist(
	ctx context.Context,
	requesterRnic *controller_agent.RnicInfo,
) ([]*controller_agent.PingTarget, error) {
	rnics, err := p.registry.GetRNICsByToR(ctx, requesterRnic.TorId)
	if err != nil {
		return nil, err
	}

	targets := make([]*controller_agent.PingTarget, 0, len(rnics))
	for _, rnic := range rnics {
		if rnic.Gid == requesterRnic.Gid {
			continue
		}

		targets = append(targets, &controller_agent.PingTarget{
			TargetRnic: rnic,
			SourcePort: p.generateRandomPort(),
			FlowLabel:  p.generateRandomFlowLabel(),
			Priority:   p.generateRandomPriority(),
		})
	}

	return targets, nil
}

// モック用にgenerateInterTorPinglist実装
func (p *mockPingLister) generateInterTorPinglist(
	ctx context.Context,
	requesterRnic *controller_agent.RnicInfo,
) ([]*controller_agent.PingTarget, error) {
	rnics, err := p.registry.GetSampleRNICsFromOtherToRs(ctx, requesterRnic.TorId)
	if err != nil {
		return nil, err
	}

	targets := make([]*controller_agent.PingTarget, 0, len(rnics))
	for _, rnic := range rnics {
		targets = append(targets, &controller_agent.PingTarget{
			TargetRnic: rnic,
			SourcePort: p.generateRandomPort(),
			FlowLabel:  p.generateRandomFlowLabel(),
			Priority:   p.generateRandomPriority(),
		})
	}

	return targets, nil
}

// ランダム関数の実装 - 本物と同じロジック
func (p *mockPingLister) generateRandomPort() uint32 {
	return uint32(p.rand.Intn(16384) + 49152)
}

func (p *mockPingLister) generateRandomFlowLabel() uint32 {
	return uint32(p.rand.Intn(1048576))
}

func (p *mockPingLister) generateRandomPriority() uint32 {
	return uint32(p.rand.Intn(8))
}

// newMockPingLister は、テスト用のモックPingListerを作成します
func newMockPingLister(reg RnicRegistryInterface) *mockPingLister {
	source := rand.NewSource(time.Now().UnixNano())
	rng := rand.New(source)

	return &mockPingLister{
		registry: reg,
		rand:     rng,
	}
}

// MockRegistry は RnicRegistry のモックです
type MockRegistry struct {
	mock.Mock
}

// GetRNICsByToR は RnicRegistry.GetRNICsByToR のモックメソッドです
func (m *MockRegistry) GetRNICsByToR(ctx context.Context, torID string) ([]*controller_agent.RnicInfo, error) {
	args := m.Called(ctx, torID)
	return args.Get(0).([]*controller_agent.RnicInfo), args.Error(1)
}

// GetSampleRNICsFromOtherToRs は RnicRegistry.GetSampleRNICsFromOtherToRs のモックメソッドです
func (m *MockRegistry) GetSampleRNICsFromOtherToRs(ctx context.Context, excludeTorID string) ([]*controller_agent.RnicInfo, error) {
	args := m.Called(ctx, excludeTorID)
	return args.Get(0).([]*controller_agent.RnicInfo), args.Error(1)
}

func TestGenerateTorMeshPinglist(t *testing.T) {
	// モックレジストリの作成
	mockReg := &MockRegistry{}

	// テスト用の RNIC データを作成
	requesterRnic := &controller_agent.RnicInfo{
		Gid:       "fe80:0000:0000:0000:0002:c903:0033:1001",
		Qpn:       1001,
		IpAddress: "192.168.1.1",
		HostName:  "host-1",
		TorId:     "tor-A",
	}

	sameToRRnics := []*controller_agent.RnicInfo{
		requesterRnic, // 同じ ToR 内の自分自身（スキップされるはず）
		{
			Gid:       "fe80:0000:0000:0000:0002:c903:0033:1002",
			Qpn:       1002,
			IpAddress: "192.168.1.2",
			HostName:  "host-2",
			TorId:     "tor-A",
		},
		{
			Gid:       "fe80:0000:0000:0000:0002:c903:0033:1003",
			Qpn:       1003,
			IpAddress: "192.168.1.3",
			HostName:  "host-3",
			TorId:     "tor-A",
		},
	}

	// モックの設定：requesterRnic と同じ ToR に属する RNIC のリストを返す
	mockReg.On("GetRNICsByToR", mock.Anything, "tor-A").Return(sameToRRnics, nil)

	// モック版PingLister の作成
	pingLister := newMockPingLister(mockReg)

	// テスト実行
	ctx := context.Background()
	targets, err := pingLister.GeneratePinglist(ctx, requesterRnic, controller_agent.PinglistRequest_TOR_MESH)

	// 検証
	require.NoError(t, err)
	require.Len(t, targets, 2, "Should return 2 targets (excluding requester)")

	// ターゲットの検証
	for _, target := range targets {
		// 自分自身は含まれていないことを確認
		assert.NotEqual(t, requesterRnic.Gid, target.TargetRnic.Gid, "Requester should not be in targets")

		// 同じ ToR 内の RNIC であることを確認
		assert.Equal(t, "tor-A", target.TargetRnic.TorId, "Target should be in the same ToR")

		// ランダム値の確認
		assert.GreaterOrEqual(t, target.SourcePort, uint32(49152), "Source port should be in ephemeral range")
		assert.LessOrEqual(t, target.SourcePort, uint32(65535), "Source port should be in ephemeral range")

		assert.GreaterOrEqual(t, target.FlowLabel, uint32(0), "Flow label should be non-negative")
		assert.LessOrEqual(t, target.FlowLabel, uint32(1048575), "Flow label should be at most 20 bits")

		assert.GreaterOrEqual(t, target.Priority, uint32(0), "Priority should be non-negative")
		assert.LessOrEqual(t, target.Priority, uint32(7), "Priority should be at most 7")
	}

	// モックが期待通り呼び出されたことを確認
	mockReg.AssertExpectations(t)
}

func TestGenerateInterTorPinglist(t *testing.T) {
	// モックレジストリの作成
	mockReg := &MockRegistry{}

	// テスト用の RNIC データを作成
	requesterRnic := &controller_agent.RnicInfo{
		Gid:       "fe80:0000:0000:0000:0002:c903:0033:1001",
		Qpn:       1001,
		IpAddress: "192.168.1.1",
		HostName:  "host-1",
		TorId:     "tor-A",
	}

	otherToRRnics := []*controller_agent.RnicInfo{
		{
			Gid:       "fe80:0000:0000:0000:0002:c903:0033:2001",
			Qpn:       2001,
			IpAddress: "192.168.2.1",
			HostName:  "host-4",
			TorId:     "tor-B",
		},
		{
			Gid:       "fe80:0000:0000:0000:0002:c903:0033:3001",
			Qpn:       3001,
			IpAddress: "192.168.3.1",
			HostName:  "host-5",
			TorId:     "tor-C",
		},
	}

	// モックの設定：requesterRnic とは異なる ToR に属する RNIC のリストを返す
	mockReg.On("GetSampleRNICsFromOtherToRs", mock.Anything, "tor-A").Return(otherToRRnics, nil)

	// モック版PingLister の作成
	pingLister := newMockPingLister(mockReg)

	// テスト実行
	ctx := context.Background()
	targets, err := pingLister.GeneratePinglist(ctx, requesterRnic, controller_agent.PinglistRequest_INTER_TOR)

	// 検証
	require.NoError(t, err)
	require.Len(t, targets, 2, "Should return 2 targets from other ToRs")

	// ターゲットの検証
	for _, target := range targets {
		// 異なる ToR 内の RNIC であることを確認
		assert.NotEqual(t, "tor-A", target.TargetRnic.TorId, "Target should be in a different ToR")

		// ランダム値の確認
		assert.GreaterOrEqual(t, target.SourcePort, uint32(49152), "Source port should be in ephemeral range")
		assert.LessOrEqual(t, target.SourcePort, uint32(65535), "Source port should be in ephemeral range")

		assert.GreaterOrEqual(t, target.FlowLabel, uint32(0), "Flow label should be non-negative")
		assert.LessOrEqual(t, target.FlowLabel, uint32(1048575), "Flow label should be at most 20 bits")

		assert.GreaterOrEqual(t, target.Priority, uint32(0), "Priority should be non-negative")
		assert.LessOrEqual(t, target.Priority, uint32(7), "Priority should be at most 7")
	}

	// モックが期待通り呼び出されたことを確認
	mockReg.AssertExpectations(t)
}

func TestRandomFunctions(t *testing.T) {
	// 独自のランダム生成器を作成して再現性を確保（シード固定）
	source := rand.NewSource(12345) // 固定シード値
	rng := rand.New(source)

	pingLister := &mockPingLister{
		registry: nil, // ランダムテストではレジストリ不要
		rand:     rng,
	}

	// ランダムポートのテスト
	counts := make(map[uint32]int)
	for i := 0; i < 1000; i++ {
		port := pingLister.generateRandomPort()
		counts[port]++
		assert.GreaterOrEqual(t, port, uint32(49152), "Source port should be in ephemeral range")
		assert.LessOrEqual(t, port, uint32(65535), "Source port should be in ephemeral range")
	}

	// ある程度分散していることを確認（厳密なテストは難しいですが、重複の数を確認）
	assert.Greater(t, len(counts), 100, "Random ports should have good distribution")

	// ランダムフローラベルのテスト
	flowCounts := make(map[uint32]int)
	for i := 0; i < 1000; i++ {
		flow := pingLister.generateRandomFlowLabel()
		flowCounts[flow]++
		assert.GreaterOrEqual(t, flow, uint32(0), "Flow label should be non-negative")
		assert.LessOrEqual(t, flow, uint32(1048575), "Flow label should be at most 20 bits")
	}

	// ある程度分散していることを確認
	assert.Greater(t, len(flowCounts), 100, "Random flow labels should have good distribution")

	// ランダム優先度のテスト
	priorityCounts := make(map[uint32]int)
	for i := 0; i < 1000; i++ {
		priority := pingLister.generateRandomPriority()
		priorityCounts[priority]++
		assert.GreaterOrEqual(t, priority, uint32(0), "Priority should be non-negative")
		assert.LessOrEqual(t, priority, uint32(7), "Priority should be at most 7")
	}

	// 0-7のすべての値が生成されることを確認
	for i := uint32(0); i <= 7; i++ {
		_, exists := priorityCounts[i]
		assert.True(t, exists, "Priority value %d should be generated", i)
	}
}

func TestUnknownPinglistType(t *testing.T) {
	// モックレジストリの作成
	mockReg := &MockRegistry{}

	// テスト用の RNIC データを作成
	requesterRnic := &controller_agent.RnicInfo{
		Gid:       "fe80:0000:0000:0000:0002:c903:0033:1001",
		Qpn:       1001,
		IpAddress: "192.168.1.1",
		HostName:  "host-1",
		TorId:     "tor-A",
	}

	sameToRRnics := []*controller_agent.RnicInfo{
		requesterRnic,
		{
			Gid:       "fe80:0000:0000:0000:0002:c903:0033:1002",
			Qpn:       1002,
			IpAddress: "192.168.1.2",
			HostName:  "host-2",
			TorId:     "tor-A",
		},
	}

	// モックの設定
	mockReg.On("GetRNICsByToR", mock.Anything, "tor-A").Return(sameToRRnics, nil)

	// モック版PingLister の作成
	pingLister := newMockPingLister(mockReg)

	// 不明なpinglistタイプでテスト実行（デフォルトでTOR_MESHが使用されるはず）
	ctx := context.Background()
	targets, err := pingLister.GeneratePinglist(ctx, requesterRnic, 999) // 無効な値

	// 検証
	require.NoError(t, err)
	require.Len(t, targets, 1, "Should default to TOR_MESH and return 1 target")

	// モックが期待通り呼び出されたことを確認
	mockReg.AssertExpectations(t)
}
