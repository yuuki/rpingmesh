//go:build linux

// Experimental, opt-in libmlx5 DC submission diagnostics. No addresses or
// process/device identifiers are emitted in the JSON statistics stream.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/yuuki/rpingmesh/internal/agent/servicetrace"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	var options servicetrace.DCOptions
	var port uint
	var check bool
	var duration time.Duration
	flag.StringVar(&options.Library, "library", "", "target process's libmlx5 ELF")
	flag.StringVar(&options.DebugFile, "debug", "", "matching full ELF/DWARF debug file")
	flag.BoolVar(&options.UCXDevX, "ucx-devx", false, "also track non-stream UCX DevX DCIs; requires matching lifecycle symbols")
	flag.BoolVar(&options.UCXAtomic, "ucx-atomic", false, "also track UCX 32/64-bit atomic post, fetch and compare-and-swap submissions")
	flag.BoolVar(&options.UCXRMA, "ucx-rma", false, "also track UCX put short/bcopy/zcopy and get bcopy/zcopy submissions")
	flag.BoolVar(&options.UCXAM, "ucx-am", false, "also track UCX AM short-iov, bcopy and zcopy submissions")
	flag.BoolVar(&options.UCXStreams, "ucx-streams", false, "also track UCX DevX DCI streams; requires -ucx-devx")
	flag.StringVar(&options.UCXLibrary, "ucx-library", "", "optional UCX dc_mlx5 provider ELF; AM-short by default")
	flag.StringVar(&options.UCXDebugFile, "ucx-debug", "", "matching full UCX ELF/DWARF debug file")
	flag.IntVar(&options.PID, "pid", 0, "target process ID; attach before DCI creation")
	flag.StringVar(&options.Device, "device", "", "RDMA device to observe")
	flag.UintVar(&port, "port", 0, "RDMA port to observe")
	flag.IntVar(&options.Capacity, "capacity", 4096, "maximum retained DC flows")
	flag.DurationVar(&options.IdleTimeout, "idle-timeout", time.Minute, "flow inactivity timeout")
	flag.DurationVar(&duration, "duration", 30*time.Second, "maximum observation duration")
	flag.BoolVar(&check, "check", false, "validate provider ELF/DWARF without loading BPF")
	flag.Parse()
	if flag.NArg() != 0 {
		return fmt.Errorf("unexpected positional arguments")
	}
	if options.UCXStreams && !options.UCXDevX {
		return fmt.Errorf("-ucx-streams requires -ucx-devx")
	}
	if check {
		if err := servicetrace.CheckDCProvider(options.Library, options.DebugFile); err != nil {
			return err
		}
		if options.UCXLibrary != "" || options.UCXDebugFile != "" {
			if err := servicetrace.CheckUCXDC(options.UCXLibrary, options.UCXDebugFile); err != nil {
				return err
			}
		}
		if options.UCXDevX {
			if err := servicetrace.CheckUCXDCDevX(options.Library, options.DebugFile, options.UCXLibrary, options.UCXDebugFile); err != nil {
				return err
			}
		}
		if options.UCXStreams {
			if err := servicetrace.CheckUCXDCStreams(options.Library, options.DebugFile, options.UCXLibrary, options.UCXDebugFile); err != nil {
				return err
			}
		}
		if options.UCXAM {
			if err := servicetrace.CheckUCXDCAM(options.UCXLibrary, options.UCXDebugFile); err != nil {
				return err
			}
		}
		if options.UCXRMA {
			if err := servicetrace.CheckUCXDCRMA(options.UCXLibrary, options.UCXDebugFile); err != nil {
				return err
			}
		}
		if options.UCXAtomic {
			if err := servicetrace.CheckUCXDCAtomic(options.UCXLibrary, options.UCXDebugFile); err != nil {
				return err
			}
		}
		fmt.Println("Provider layout validated; BPF was not loaded.")
		return nil
	}
	if port == 0 || port > 255 || duration <= 0 || options.Capacity <= 0 || options.IdleTimeout <= 0 {
		return fmt.Errorf("port must be 1..255; duration, capacity and idle-timeout must be positive")
	}
	options.Port = uint8(port)
	collector, err := servicetrace.OpenDCCollector(options)
	if err != nil {
		return err
	}
	defer collector.Close()
	signals, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(signals, duration)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- collector.Run(ctx) }()
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	encode := json.NewEncoder(os.Stdout)
	write := func() error {
		stats, err := collector.Stats()
		if err != nil {
			return err
		}
		return encode.Encode(stats)
	}
	for {
		select {
		case err := <-done:
			if err != nil {
				return err
			}
			return write()
		case <-tick.C:
			if err := write(); err != nil {
				cancel()
				<-done
				return err
			}
		}
	}
}
