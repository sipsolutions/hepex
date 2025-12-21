package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

const liveSnapLen uint32 = 65535

func captureLiveToTemp(iface, bpfFilter string) (string, error) {
	handle, err := pcap.OpenLive(iface, int32(liveSnapLen), true, pcap.BlockForever)
	if err != nil {
		return "", fmt.Errorf("open live capture on %s: %w", iface, err)
	}
	defer handle.Close()

	if bpfFilter != "" {
		if err := handle.SetBPFFilter(bpfFilter); err != nil {
			return "", fmt.Errorf("set BPF filter: %w", err)
		}
	}

	tmpFile, err := os.CreateTemp("", "hepex-live-*.pcap")
	if err != nil {
		return "", fmt.Errorf("create temp pcap: %w", err)
	}
	defer tmpFile.Close()

	writer := pcapgo.NewWriter(tmpFile)
	if err := writer.WriteFileHeader(liveSnapLen, handle.LinkType()); err != nil {
		return "", fmt.Errorf("write pcap header: %w", err)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	go func() {
		<-sigCh
		handle.Close()
	}()

	source := gopacket.NewPacketSource(handle, handle.LinkType())
	count := 0
	for packet := range source.Packets() {
		if err := writer.WritePacket(packet.Metadata().CaptureInfo, packet.Data()); err != nil {
			return "", fmt.Errorf("write pcap packet: %w", err)
		}
		count++
	}

	log.Printf("Captured %d packets to %s", count, tmpFile.Name())
	return tmpFile.Name(), nil
}
