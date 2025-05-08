package upload

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/yuuki/rpingmesh/proto/agent_analyzer"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials/insecure"
)

// Uploader uploads data to the analyzer
type Uploader struct {
	addr           string
	conn           *grpc.ClientConn
	client         agent_analyzer.AnalyzerServiceClient
	agentID        string
	probeResults   []*agent_analyzer.ProbeResult
	pathInfos      []*agent_analyzer.PathInfo
	mutex          sync.Mutex
	uploadInterval time.Duration
	batchSize      int
	maxQueueSize   int
	ctx            context.Context
	cancel         context.CancelFunc
	wg             sync.WaitGroup
	running        bool
}

// NewUploader creates a new uploader
func NewUploader(addr, agentID string, uploadIntervalMs uint32, batchSize, maxQueueSize int) *Uploader {
	ctx, cancel := context.WithCancel(context.Background())
	return &Uploader{
		addr:           addr,
		agentID:        agentID,
		uploadInterval: time.Duration(uploadIntervalMs) * time.Millisecond,
		batchSize:      batchSize,
		maxQueueSize:   maxQueueSize,
		probeResults:   make([]*agent_analyzer.ProbeResult, 0, maxQueueSize),
		pathInfos:      make([]*agent_analyzer.PathInfo, 0, 100),
		ctx:            ctx,
		cancel:         cancel,
		running:        false,
	}
}

// Connect connects to the analyzer
func (u *Uploader) Connect() error {
	u.mutex.Lock()
	defer u.mutex.Unlock()

	// If already connected, return
	if u.conn != nil {
		log.Debug().Msg("Already connected to analyzer")
		return nil
	}

	log.Debug().Str("addr", u.addr).Msg("Connecting to analyzer...")

	// Connect with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Establish connection without TLS for now
	// In production, should use TLS credentials
	conn, err := grpc.NewClient(u.addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return fmt.Errorf("failed to connect to analyzer at %s: %w", u.addr, err)
	}

	// Wait for connection to be READY state with timeout
	for {
		select {
		case <-ctx.Done():
			if conn != nil {
				conn.Close()
			}
			return fmt.Errorf("timeout connecting to analyzer at %s", u.addr)
		default:
			state := conn.GetState()
			log.Debug().Str("state", state.String()).Msg("Connection state")
			if state == connectivity.Ready {
				u.conn = conn
				u.client = agent_analyzer.NewAnalyzerServiceClient(conn)
				log.Info().Str("addr", u.addr).Msg("Connected to analyzer")
				return nil
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
}

// Start starts the uploader
func (u *Uploader) Start() error {
	if u.running {
		return nil
	}

	if u.client == nil {
		if err := u.Connect(); err != nil {
			return err
		}
	}

	u.running = true
	u.wg.Add(1)
	go u.uploadLoop()

	log.Info().
		Str("addr", u.addr).
		Dur("interval", u.uploadInterval).
		Int("batchSize", u.batchSize).
		Msg("Uploader started")

	return nil
}

// Stop stops the uploader
func (u *Uploader) Stop() {
	u.mutex.Lock()
	defer u.mutex.Unlock()

	if !u.running {
		return
	}

	u.cancel()
	u.wg.Wait()
	u.running = false
	log.Info().Msg("Uploader stopped")
}

// Close closes the uploader
func (u *Uploader) Close() error {
	u.Stop()

	u.mutex.Lock()
	defer u.mutex.Unlock()

	if u.conn != nil {
		if err := u.conn.Close(); err != nil {
			return err
		}
		u.conn = nil
		u.client = nil
	}

	return nil
}

// AddProbeResult adds a probe result to the upload queue
func (u *Uploader) AddProbeResult(result *agent_analyzer.ProbeResult) {
	u.mutex.Lock()
	defer u.mutex.Unlock()

	// Add to queue
	u.probeResults = append(u.probeResults, result)
	log.Debug().
		Int("queueSize", len(u.probeResults)).
		Int("maxQueueSize", u.maxQueueSize).
		Msg("Added probe result to queue")

	// If queue is full, trigger upload
	if len(u.probeResults) >= u.maxQueueSize {
		log.Debug().
			Int("queueSize", len(u.probeResults)).
			Msg("Queue is full, triggering immediate upload")
		// Trigger immediate upload in a goroutine to avoid blocking
		go func() {
			if err := u.uploadData(); err != nil {
				log.Error().Err(err).Msg("Failed to upload data when queue was full")
			}
		}()
	}
}

// AddPathInfo adds a path info to the upload queue
func (u *Uploader) AddPathInfo(pathInfo *agent_analyzer.PathInfo) {
	u.mutex.Lock()
	defer u.mutex.Unlock()

	u.pathInfos = append(u.pathInfos, pathInfo)
	log.Debug().
		Int("pathInfoCount", len(u.pathInfos)).
		Msg("Added path info to queue")
}

// uploadLoop periodically uploads data to the analyzer
func (u *Uploader) uploadLoop() {
	defer u.wg.Done()

	ticker := time.NewTicker(u.uploadInterval)
	defer ticker.Stop()

	for {
		select {
		case <-u.ctx.Done():
			// Upload any remaining data before exiting
			_ = u.uploadData()
			return
		case <-ticker.C:
			if err := u.uploadData(); err != nil {
				log.Error().Err(err).Msg("Failed to upload data")
				// Try to reconnect on next tick
				u.mutex.Lock()
				u.conn = nil
				u.client = nil
				u.mutex.Unlock()
			}
		}
	}
}

// uploadData uploads the pending data to the analyzer
func (u *Uploader) uploadData() error {
	// Check if there's anything to upload
	if len(u.probeResults) == 0 && len(u.pathInfos) == 0 {
		log.Debug().Msg("No data to upload")
		return nil
	}

	log.Debug().
		Int("pendingProbeResults", len(u.probeResults)).
		Int("pendingPathInfos", len(u.pathInfos)).
		Msg("Starting data upload")

	// Check connection
	if u.client == nil {
		log.Debug().Msg("Client is nil, attempting to reconnect")
		if err := u.Connect(); err != nil {
			return err
		}
	}

	// Prepare batch
	var results []*agent_analyzer.ProbeResult
	var pathInfos []*agent_analyzer.PathInfo

	// Take up to batchSize results
	if len(u.probeResults) > u.batchSize {
		results = u.probeResults[:u.batchSize]
		u.probeResults = u.probeResults[u.batchSize:]
		log.Debug().
			Int("batchSize", len(results)).
			Int("remainingResults", len(u.probeResults)).
			Msg("Split probe results into batch")
	} else {
		results = u.probeResults
		u.probeResults = make([]*agent_analyzer.ProbeResult, 0, u.maxQueueSize)
		log.Debug().
			Int("batchSize", len(results)).
			Msg("Using all probe results as batch")
	}

	// Take all path infos
	pathInfos = u.pathInfos
	u.pathInfos = make([]*agent_analyzer.PathInfo, 0, 100)
	log.Debug().
		Int("pathInfoCount", len(pathInfos)).
		Msg("Prepared path infos for upload")

	// Create request
	req := &agent_analyzer.UploadDataRequest{
		AgentId:      u.agentID,
		ProbeResults: results,
		PathInfos:    pathInfos,
	}

	// Send request with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := u.client.UploadData(ctx, req)
	if err != nil {
		// In case of failure, put the data back in the queue
		u.mutex.Lock()
		u.probeResults = append(results, u.probeResults...)
		u.pathInfos = append(pathInfos, u.pathInfos...)
		u.mutex.Unlock()
		return fmt.Errorf("failed to upload data: %w", err)
	}

	if !resp.Success {
		// Similarly, in case of failure, put the data back in the queue
		u.mutex.Lock()
		u.probeResults = append(results, u.probeResults...)
		u.pathInfos = append(pathInfos, u.pathInfos...)
		u.mutex.Unlock()
		return fmt.Errorf("upload failed: %s", resp.Message)
	}

	log.Debug().
		Int("probeResults", len(results)).
		Int("pathInfos", len(pathInfos)).
		Msg("Successfully uploaded data to analyzer")

	return nil
}
