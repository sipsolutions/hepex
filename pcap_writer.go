package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

var (
	// Regex to match a=crypto lines
	cryptoLineRegex = regexp.MustCompile(`(?m)^a=crypto:[^\r\n]*\r?\n`)
)

// DialogWriter manages pcap writers for each dialog
type DialogWriter struct {
	sync.Mutex
	outputDir   string
	writers     map[string]*pcapgo.Writer
	files       map[string]*os.File
	sanitizeSDP bool // whether to convert SAVP->AVP and remove crypto lines
}

// NewDialogWriter creates a new dialog writer
// If sanitizeSDP is true, SDP will be modified to indicate plain RTP (for decrypted output)
func NewDialogWriter(outputDir string, sanitizeSDP bool) (*DialogWriter, error) {
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create output directory: %w", err)
	}

	return &DialogWriter{
		outputDir:   outputDir,
		writers:     make(map[string]*pcapgo.Writer),
		files:       make(map[string]*os.File),
		sanitizeSDP: sanitizeSDP,
	}, nil
}

// GetWriter returns a writer for the given dialog filename
func (dw *DialogWriter) GetWriter(filename string) (*pcapgo.Writer, error) {
	dw.Lock()
	defer dw.Unlock()

	if w, ok := dw.writers[filename]; ok {
		return w, nil
	}

	// Create new file
	path := filepath.Join(dw.outputDir, filename)
	f, err := os.Create(path)
	if err != nil {
		return nil, fmt.Errorf("failed to create pcap file: %w", err)
	}

	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		f.Close()
		return nil, fmt.Errorf("failed to write pcap header: %w", err)
	}

	dw.files[filename] = f
	dw.writers[filename] = w

	return w, nil
}

// Close closes all open files
func (dw *DialogWriter) Close() error {
	dw.Lock()
	defer dw.Unlock()

	var lastErr error
	for _, f := range dw.files {
		if err := f.Close(); err != nil {
			lastErr = err
		}
	}
	return lastErr
}

// WriteSIPPacket writes a SIP packet to the dialog pcap
// If sanitizeSDP is enabled, it modifies SDP to indicate plain RTP instead of SRTP
func (dw *DialogWriter) WriteSIPPacket(filename string, sipPayload []byte, srcIP, dstIP net.IP, srcPort, dstPort uint16, timestamp time.Time) error {
	w, err := dw.GetWriter(filename)
	if err != nil {
		return err
	}

	payload := sipPayload
	if dw.sanitizeSDP {
		// Sanitize SDP: change RTP/SAVP to RTP/AVP and remove crypto lines
		payload = sanitizeSDP(sipPayload)
	}

	pkt := buildUDPPacket(payload, srcIP, dstIP, srcPort, dstPort)

	ci := gopacket.CaptureInfo{
		Timestamp:     timestamp,
		CaptureLength: len(pkt),
		Length:        len(pkt),
	}

	dw.Lock()
	defer dw.Unlock()
	return w.WritePacket(ci, pkt)
}

// sanitizeSDP modifies SDP to indicate plain RTP instead of SRTP
func sanitizeSDP(payload []byte) []byte {
	// Replace RTP/SAVP with RTP/AVP (no trailing space)
	result := bytes.ReplaceAll(payload, []byte("RTP/SAVP"), []byte("RTP/AVP"))

	// Remove a=crypto lines
	result = cryptoLineRegex.ReplaceAll(result, []byte{})

	// Update Content-Length if present
	result = updateContentLength(result)

	return result
}

// updateContentLength recalculates the Content-Length header in SIP message
func updateContentLength(payload []byte) []byte {
	// Find the header/body separator
	sep := []byte("\r\n\r\n")
	sepIdx := bytes.Index(payload, sep)
	if sepIdx < 0 {
		sep = []byte("\n\n")
		sepIdx = bytes.Index(payload, sep)
	}
	if sepIdx < 0 {
		return payload
	}

	header := payload[:sepIdx]
	body := payload[sepIdx+len(sep):]
	bodyLen := len(body)

	// Find and replace Content-Length header
	clRegex := regexp.MustCompile(`(?i)Content-Length:\s*\d+`)
	newCL := fmt.Sprintf("Content-Length: %d", bodyLen)
	newHeader := clRegex.ReplaceAll(header, []byte(newCL))

	// Reconstruct the message
	result := make([]byte, 0, len(newHeader)+len(sep)+len(body))
	result = append(result, newHeader...)
	result = append(result, sep...)
	result = append(result, body...)

	return result
}

// WriteRTPPacket writes an RTP packet to the dialog pcap
func (dw *DialogWriter) WriteRTPPacket(filename string, rtpPayload []byte, srcIP, dstIP net.IP, srcPort, dstPort uint16, timestamp time.Time) error {
	w, err := dw.GetWriter(filename)
	if err != nil {
		return err
	}

	pkt := buildUDPPacket(rtpPayload, srcIP, dstIP, srcPort, dstPort)

	ci := gopacket.CaptureInfo{
		Timestamp:     timestamp,
		CaptureLength: len(pkt),
		Length:        len(pkt),
	}

	dw.Lock()
	defer dw.Unlock()
	return w.WritePacket(ci, pkt)
}

// buildUDPPacket constructs a complete Ethernet/IP/UDP packet
func buildUDPPacket(payload []byte, srcIP, dstIP net.IP, srcPort, dstPort uint16) []byte {
	// Ethernet header (14 bytes)
	eth := make([]byte, 14)
	// Dst MAC (dummy)
	eth[0], eth[1], eth[2], eth[3], eth[4], eth[5] = 0x00, 0x00, 0x00, 0x00, 0x00, 0x02
	// Src MAC (dummy)
	eth[6], eth[7], eth[8], eth[9], eth[10], eth[11] = 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
	// EtherType IPv4
	binary.BigEndian.PutUint16(eth[12:], 0x0800)

	ipHeader := buildIPv4Header(srcIP.To4(), dstIP.To4(), len(payload)+8)

	// UDP header (8 bytes)
	udp := make([]byte, 8)
	binary.BigEndian.PutUint16(udp[0:], srcPort)
	binary.BigEndian.PutUint16(udp[2:], dstPort)
	binary.BigEndian.PutUint16(udp[4:], uint16(8+len(payload)))
	binary.BigEndian.PutUint16(udp[6:], 0) // Checksum (optional for IPv4)

	// Combine all parts
	result := make([]byte, 0, len(eth)+len(ipHeader)+len(udp)+len(payload))
	result = append(result, eth...)
	result = append(result, ipHeader...)
	result = append(result, udp...)
	result = append(result, payload...)

	return result
}

func buildIPv4Header(srcIP, dstIP []byte, payloadLen int) []byte {
	totalLen := 20 + payloadLen
	ip := make([]byte, 20)

	ip[0] = 0x45                                       // Version (4) + IHL (5)
	ip[1] = 0                                          // DSCP + ECN
	binary.BigEndian.PutUint16(ip[2:], uint16(totalLen))
	binary.BigEndian.PutUint16(ip[4:], 0)             // ID
	binary.BigEndian.PutUint16(ip[6:], 0x4000)        // Flags (Don't Fragment)
	ip[8] = 64                                         // TTL
	ip[9] = 17                                         // Protocol (UDP)
	binary.BigEndian.PutUint16(ip[10:], 0)            // Checksum (will be calculated)
	copy(ip[12:16], srcIP)
	copy(ip[16:20], dstIP)

	// Calculate checksum
	var sum uint32
	for i := 0; i < 20; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(ip[i:]))
	}
	for sum > 0xFFFF {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	binary.BigEndian.PutUint16(ip[10:], ^uint16(sum))

	return ip
}
