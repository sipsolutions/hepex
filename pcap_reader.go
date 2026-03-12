package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// Packet represents a captured UDP packet with metadata
type Packet struct {
	Timestamp time.Time
	SrcIP     string
	DstIP     string
	SrcPort   uint16
	DstPort   uint16
	IsHEP     bool
	Payload   []byte
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
	pkt.Payload = udp.Payload

	if isHEPPayload(pkt.Payload) {
		pkt.IsHEP = true
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
	tracker       *DialogTracker
	writer        *DialogWriter
	srtpContexts  map[string]*SRTPContext
	fromFilter    string
	toFilter      string
	dialogMaxIdle time.Duration
	debug         bool
	lastPrune     time.Time

	sipWritten       int
	rtpWritten       int
	rtpDecrypted     int
	rtpDecryptFailed int
	rtpUnmatched     int
	sipDropped       int
	rtpDropped       int
}

func NewLiveProcessor(tracker *DialogTracker, writer *DialogWriter, fromFilter, toFilter string, debug bool, dialogMaxIdle time.Duration) *LiveProcessor {
	return &LiveProcessor{
		tracker:       tracker,
		writer:        writer,
		srtpContexts:  make(map[string]*SRTPContext),
		fromFilter:    fromFilter,
		toFilter:      toFilter,
		dialogMaxIdle: dialogMaxIdle,
		debug:         debug,
		lastPrune:     time.Now(),
	}
}

func (p *LiveProcessor) ProcessPacket(pkt *Packet) error {
	p.pruneExpiredDialogs(pkt.Timestamp)

	if pkt.IsHEP && len(pkt.Payload) > 0 {
		return p.processHEPSIP(pkt)
	}

	if len(pkt.Payload) > 0 && !pkt.IsHEP {
		return p.processRTP(pkt)
	}
	return nil
}

func (p *LiveProcessor) processHEPSIP(pkt *Packet) error {
	hepPkt, err := ParseHEP(pkt.Payload)
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

	dialog := p.tracker.ProcessSIPMessage(sipMsg, hepPkt.SrcIP.String(), hepPkt.Timestamp)
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
	if !IsRTPPacket(pkt.Payload) {
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

	dialog.LastSeen = pkt.Timestamp

	if !dialog.HasCrypto() || !dialog.MatchesFilters(p.fromFilter, p.toFilter) {
		p.rtpDropped++
		return nil
	}

	return p.writeRTP(dialog, pkt.Payload, srcIP, dstIP, pkt.SrcPort, pkt.DstPort, pkt.Timestamp)
}

func (p *LiveProcessor) srtpContextForEndpoints(srcIP, dstIP net.IP, srcPort, dstPort uint16) *SRTPContext {
	if srcIP == nil || dstIP == nil {
		return nil
	}
	srcKey := mediaAddressKey(srcIP.String(), int(srcPort))
	if c, ok := p.srtpContexts[srcKey]; ok {
		return c
	}
	dstKey := mediaAddressKey(dstIP.String(), int(dstPort))
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
	oldKeys := dialog.ContextKeys
	dialog.ContextKeys = nil
	desiredKeys := make(map[string]struct{})

	for _, ms := range dialog.MediaStreams {
		if len(ms.MasterKey) == 0 || len(ms.MasterSalt) == 0 {
			continue
		}
		key := mediaAddressKey(ms.LocalIP.String(), ms.LocalPort)
		desiredKeys[key] = struct{}{}
		if _, exists := p.srtpContexts[key]; exists {
			continue
		}
		ctx, err := NewSRTPContext(ms.MasterKey, ms.MasterSalt)
		if err != nil {
			continue
		}
		p.srtpContexts[key] = ctx
	}

	for _, key := range oldKeys {
		if _, keep := desiredKeys[key]; keep {
			continue
		}
		delete(p.srtpContexts, key)
	}

	for key := range desiredKeys {
		dialog.ContextKeys = append(dialog.ContextKeys, key)
	}
}

func (p *LiveProcessor) pruneExpiredDialogs(now time.Time) {
	const pruneInterval = time.Minute

	if !p.lastPrune.IsZero() && now.Sub(p.lastPrune) < pruneInterval {
		return
	}

	for _, dialog := range p.tracker.PruneExpired(now, p.dialogMaxIdle) {
		p.removeDialogSRTPContexts(dialog)
	}
	p.lastPrune = now
}

func (p *LiveProcessor) removeDialogSRTPContexts(dialog *Dialog) {
	for _, key := range dialog.ContextKeys {
		delete(p.srtpContexts, key)
	}
	dialog.ContextKeys = nil
}
