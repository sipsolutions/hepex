package main

import (
	"encoding/binary"
	"fmt"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// Packet represents a captured packet with metadata
type Packet struct {
	Timestamp  time.Time
	SrcIP      string
	DstIP      string
	SrcPort    uint16
	DstPort    uint16
	IsHEP      bool
	HEPPayload []byte
	IsUDP      bool
	UDPPayload []byte
}

// Reader reads packets from a pcap file
type Reader struct {
	handle *pcap.Handle
	source *gopacket.PacketSource
}

// NewReader creates a new pcap reader
func NewReader(filename string, bpfFilter string) (*Reader, error) {
	handle, err := pcap.OpenOffline(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open pcap: %w", err)
	}
	if bpfFilter != "" {
		if err := handle.SetBPFFilter(bpfFilter); err != nil {
			handle.Close()
			return nil, fmt.Errorf("failed to set BPF filter: %w", err)
		}
	}

	source := gopacket.NewPacketSource(handle, handle.LinkType())

	return &Reader{
		handle: handle,
		source: source,
	}, nil
}

// Close closes the pcap handle
func (r *Reader) Close() {
	if r.handle != nil {
		r.handle.Close()
	}
}

// ForEach calls fn for every parsed packet.
func (r *Reader) ForEach(fn func(*Packet) error) error {
	for packet := range r.source.Packets() {
		pkt := parsePacket(packet)
		if pkt == nil {
			continue
		}
		if err := fn(pkt); err != nil {
			return err
		}
	}
	return nil
}

func parsePacket(packet gopacket.Packet) *Packet {
	pkt := &Packet{
		Timestamp: packet.Metadata().Timestamp,
	}

	// Extract IP info
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip := ipLayer.(*layers.IPv4)
		pkt.SrcIP = ip.SrcIP.String()
		pkt.DstIP = ip.DstIP.String()
	}

	// Extract UDP info
	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp := udpLayer.(*layers.UDP)
		pkt.SrcPort = uint16(udp.SrcPort)
		pkt.DstPort = uint16(udp.DstPort)
		pkt.IsUDP = true
		pkt.UDPPayload = udp.Payload

		if isHEPPayload(udp.Payload) {
			pkt.IsHEP = true
			pkt.HEPPayload = udp.Payload
		}
	}

	return pkt
}

func isHEPPayload(payload []byte) bool {
	if len(payload) < 6 {
		return false
	}
	if string(payload[0:4]) != "HEP3" {
		return false
	}
	totalLen := binary.BigEndian.Uint16(payload[4:6])
	if totalLen < 6 || int(totalLen) > len(payload) {
		return false
	}
	return true
}
