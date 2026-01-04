package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"syscall"
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
	for {
		packet, err := r.source.NextPacket()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("failed to read packet: %w", err)
		}
		pkt := parsePacket(packet)
		if pkt == nil {
			continue
		}
		if err := fn(pkt); err != nil {
			return err
		}
	}
}

func parsePacket(packet gopacket.Packet) *Packet {
	// Only UDP is used by the rest of the pipeline.
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		return nil
	}

	pkt := &Packet{
		Timestamp: packet.Metadata().Timestamp,
	}

	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip := ipLayer.(*layers.IPv4)
		pkt.SrcIP = ip.SrcIP.String()
		pkt.DstIP = ip.DstIP.String()
	}

	udp := udpLayer.(*layers.UDP)
	pkt.SrcPort = uint16(udp.SrcPort)
	pkt.DstPort = uint16(udp.DstPort)
	pkt.IsUDP = true
	pkt.UDPPayload = udp.Payload

	if isHEPPayload(udp.Payload) {
		pkt.IsHEP = true
		pkt.HEPPayload = udp.Payload
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

const liveSnapLen uint32 = 65535

func openLiveSource(iface, bpfFilter string) (*pcap.Handle, *gopacket.PacketSource, error) {
	handle, err := pcap.OpenLive(iface, int32(liveSnapLen), true, pcap.BlockForever)
	if err != nil {
		return nil, nil, fmt.Errorf("open live capture on %s: %w", iface, err)
	}

	if bpfFilter != "" {
		if err := handle.SetBPFFilter(bpfFilter); err != nil {
			handle.Close()
			return nil, nil, fmt.Errorf("set BPF filter: %w", err)
		}
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		handle.Close()
		signal.Stop(sigCh)
	}()

	source := gopacket.NewPacketSource(handle, handle.LinkType())
	return handle, source, nil
}

type LiveProcessor struct {
	tracker      *DialogTracker
	writer       *DialogWriter
	srtpContexts map[string]*SRTPContext
	fromFilter   string
	toFilter     string
	debug        bool

	sipWritten       int
	rtpWritten       int
	rtpDecrypted     int
	rtpDecryptFailed int
	rtpUnmatched     int
	sipDropped       int
	rtpDropped       int
}

func NewLiveProcessor(tracker *DialogTracker, writer *DialogWriter, fromFilter, toFilter string, debug bool) *LiveProcessor {
	return &LiveProcessor{
		tracker:      tracker,
		writer:       writer,
		srtpContexts: make(map[string]*SRTPContext),
		fromFilter:   fromFilter,
		toFilter:     toFilter,
		debug:        debug,
	}
}

func (p *LiveProcessor) ProcessPacket(pkt *Packet) error {
	if pkt.IsHEP && len(pkt.HEPPayload) > 0 {
		return p.processHEPSIP(pkt)
	}

	if pkt.IsUDP && len(pkt.UDPPayload) > 0 && !pkt.IsHEP {
		return p.processRTP(pkt)
	}
	return nil
}

func (p *LiveProcessor) processHEPSIP(pkt *Packet) error {
	hepPkt, err := ParseHEP(pkt.HEPPayload)
	if err != nil {
		return nil
	}
	if !hepPkt.IsSIP() || len(hepPkt.Payload) == 0 {
		return nil
	}

	sipMsg, err := ParseSIP(hepPkt.Payload)
	if err != nil || sipMsg == nil {
		return nil
	}

	dialog := p.tracker.ProcessSIPMessage(sipMsg, hepPkt.Timestamp)
	if dialog != nil {
		p.addDialogSRTPContexts(dialog)
	}

	if dialog != nil && dialog.HasCrypto() && dialog.MatchesFilters(p.fromFilter, p.toFilter) {
		return p.writeSIP(hepPkt, dialog)
	}

	p.sipDropped++
	return nil
}

func (p *LiveProcessor) processRTP(pkt *Packet) error {
	if !IsRTPPacket(pkt.UDPPayload) {
		return nil
	}

	srcIP := net.ParseIP(pkt.SrcIP)
	dstIP := net.ParseIP(pkt.DstIP)
	if srcIP == nil || dstIP == nil {
		return nil
	}

	dialog := p.tracker.FindDialogForMedia(
		srcIP, int(pkt.SrcPort),
		dstIP, int(pkt.DstPort),
	)
	if dialog == nil {
		p.rtpUnmatched++
		return nil
	}

	if !dialog.HasCrypto() || !dialog.MatchesFilters(p.fromFilter, p.toFilter) {
		p.rtpDropped++
		return nil
	}

	return p.writeRTP(dialog, pkt.UDPPayload, srcIP, dstIP, pkt.SrcPort, pkt.DstPort, pkt.Timestamp)
}

func (p *LiveProcessor) srtpContextForEndpoints(srcIP, dstIP net.IP, srcPort, dstPort uint16) *SRTPContext {
	if srcIP == nil || dstIP == nil {
		return nil
	}
	srcKey := fmt.Sprintf("%s:%d", srcIP.String(), srcPort)
	if c, ok := p.srtpContexts[srcKey]; ok {
		return c
	}
	dstKey := fmt.Sprintf("%s:%d", dstIP.String(), dstPort)
	if c, ok := p.srtpContexts[dstKey]; ok {
		return c
	}
	return nil
}

func (p *LiveProcessor) writeSIP(hepPkt *HEPPacket, dialog *Dialog) error {
	filename := dialog.Filename()
	if err := p.writer.WriteSIPPacket(
		filename,
		hepPkt.Payload,
		hepPkt.SrcIP, hepPkt.DstIP,
		hepPkt.SrcPort, hepPkt.DstPort,
		hepPkt.Timestamp,
	); err != nil {
		return fmt.Errorf("write SIP packet: %w", err)
	}
	p.sipWritten++
	return nil
}

func (p *LiveProcessor) writeRTP(dialog *Dialog, payload []byte, srcIP, dstIP net.IP, srcPort, dstPort uint16, timestamp time.Time) error {
	filename := dialog.Filename()
	rtpPayload := payload

	ctx := p.srtpContextForEndpoints(srcIP, dstIP, srcPort, dstPort)

	if ctx != nil {
		decrypted, err := ctx.DecryptRTP(rtpPayload)
		if err == nil {
			rtpPayload = decrypted
			p.rtpDecrypted++
		} else {
			p.rtpDecryptFailed++
		}
	}

	if err := p.writer.WriteRTPPacket(
		filename,
		rtpPayload,
		srcIP, dstIP,
		srcPort, dstPort,
		timestamp,
	); err != nil {
		return fmt.Errorf("write RTP packet: %w", err)
	}
	p.rtpWritten++
	return nil
}

func (p *LiveProcessor) addDialogSRTPContexts(dialog *Dialog) {
	for _, ms := range dialog.MediaStreams {
		if len(ms.MasterKey) == 0 || len(ms.MasterSalt) == 0 {
			continue
		}
		key := fmt.Sprintf("%s:%d", ms.LocalIP, ms.LocalPort)
		if _, exists := p.srtpContexts[key]; exists {
			continue
		}
		ctx, err := NewSRTPContext(ms.MasterKey, ms.MasterSalt)
		if err != nil {
			continue
		}
		p.srtpContexts[key] = ctx
	}
}
