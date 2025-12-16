package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"
)

// HEPv3 chunk types
const (
	ChunkIPProtocolID  = 0x0002
	ChunkIPv4Src       = 0x0003
	ChunkIPv4Dst       = 0x0004
	ChunkSrcPort       = 0x0007
	ChunkDstPort       = 0x0008
	ChunkTimestampSec  = 0x0009
	ChunkTimestampUsec = 0x000a
	ChunkProtocolType  = 0x000b
	ChunkPayload       = 0x000f
)

// Protocol types
const (
	ProtocolSIP = 0x01
)

// HEPPacket represents a parsed HEPv3 packet
type HEPPacket struct {
	ProtocolID   uint8 // 6=TCP, 17=UDP
	SrcIP        net.IP
	DstIP        net.IP
	SrcPort      uint16
	DstPort      uint16
	Timestamp    time.Time
	ProtocolType uint8 // SIP
	Payload      []byte
}

// ParseHEP parses a HEPv3 packet from raw bytes
func ParseHEP(data []byte) (*HEPPacket, error) {
	if len(data) < 6 {
		return nil, errors.New("packet too short for HEP header")
	}

	// Check HEP header
	if string(data[0:4]) != "HEP3" {
		return nil, errors.New("not a HEPv3 packet")
	}

	totalLen := binary.BigEndian.Uint16(data[4:6])
	if int(totalLen) > len(data) {
		return nil, fmt.Errorf("packet truncated: header says %d, got %d", totalLen, len(data))
	}

	pkt := &HEPPacket{}

	// Parse chunks
	offset := 6
	for offset < int(totalLen) {
		if offset+6 > len(data) {
			break
		}

		// vendorID := binary.BigEndian.Uint16(data[offset:])
		chunkType := binary.BigEndian.Uint16(data[offset+2:])
		chunkLen := binary.BigEndian.Uint16(data[offset+4:])

		if chunkLen < 6 {
			return nil, fmt.Errorf("invalid chunk length: %d", chunkLen)
		}

		payloadLen := int(chunkLen) - 6
		if offset+6+payloadLen > len(data) {
			return nil, errors.New("chunk extends beyond packet")
		}

		chunkData := data[offset+6 : offset+int(chunkLen)]

		switch chunkType {
		case ChunkIPProtocolID:
			if len(chunkData) >= 1 {
				pkt.ProtocolID = chunkData[0]
			}
		case ChunkIPv4Src:
			if len(chunkData) >= 4 {
				pkt.SrcIP = net.IP(chunkData[:4])
			}
		case ChunkIPv4Dst:
			if len(chunkData) >= 4 {
				pkt.DstIP = net.IP(chunkData[:4])
			}
		case ChunkSrcPort:
			if len(chunkData) >= 2 {
				pkt.SrcPort = binary.BigEndian.Uint16(chunkData)
			}
		case ChunkDstPort:
			if len(chunkData) >= 2 {
				pkt.DstPort = binary.BigEndian.Uint16(chunkData)
			}
		case ChunkTimestampSec:
			if len(chunkData) >= 4 {
				sec := binary.BigEndian.Uint32(chunkData)
				pkt.Timestamp = time.Unix(int64(sec), pkt.Timestamp.UnixNano()%1e9)
			}
		case ChunkTimestampUsec:
			if len(chunkData) >= 4 {
				usec := binary.BigEndian.Uint32(chunkData)
				pkt.Timestamp = time.Unix(pkt.Timestamp.Unix(), int64(usec)*1000)
			}
		case ChunkProtocolType:
			if len(chunkData) >= 1 {
				pkt.ProtocolType = chunkData[0]
			}
		case ChunkPayload:
			pkt.Payload = make([]byte, len(chunkData))
			copy(pkt.Payload, chunkData)
		}

		offset += int(chunkLen)
	}

	return pkt, nil
}

// IsSIP returns true if this is a SIP packet
func (p *HEPPacket) IsSIP() bool {
	return p.ProtocolType == ProtocolSIP
}

// IsTLS returns true if the original capture was over TCP (TLS)
func (p *HEPPacket) IsTLS() bool {
	return p.ProtocolID == 6
}

// ProtocolTypeName returns human-readable protocol type name
func (p *HEPPacket) ProtocolTypeName() string {
	if p.ProtocolType == ProtocolSIP {
		return "SIP"
	}
	return fmt.Sprintf("UNKNOWN(%d)", p.ProtocolType)
}
