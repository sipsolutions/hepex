package main

import (
	"fmt"
	"sync"

	"github.com/pion/srtp/v3"
)

// SRTPContext holds SRTP session state using pion/srtp
type SRTPContext struct {
	sync.Mutex
	srtpCtx *srtp.Context
}

// NewSRTPContext creates a new SRTP context with the given master key and salt
func NewSRTPContext(masterKey, masterSalt []byte) (*SRTPContext, error) {
	if len(masterKey) != 16 {
		return nil, fmt.Errorf("master key must be 16 bytes, got %d", len(masterKey))
	}
	if len(masterSalt) < 14 {
		return nil, fmt.Errorf("master salt must be at least 14 bytes, got %d", len(masterSalt))
	}

	srtpCtx, err := srtp.CreateContext(masterKey, masterSalt[:14], srtp.ProtectionProfileAes128CmHmacSha1_80)
	if err != nil {
		return nil, fmt.Errorf("failed to create SRTP context: %w", err)
	}

	return &SRTPContext{srtpCtx: srtpCtx}, nil
}

// DecryptRTP decrypts an SRTP packet and returns the RTP payload
func (ctx *SRTPContext) DecryptRTP(packet []byte) ([]byte, error) {
	ctx.Lock()
	defer ctx.Unlock()

	// pion/srtp decrypts in place, so make a copy
	buf := make([]byte, len(packet))
	copy(buf, packet)

	decrypted, err := ctx.srtpCtx.DecryptRTP(nil, buf, nil)
	if err != nil {
		return nil, fmt.Errorf("SRTP decrypt failed: %w", err)
	}

	return decrypted, nil
}

// IsRTPPacket checks if the data looks like an RTP packet
func IsRTPPacket(data []byte) bool {
	if len(data) < 12 {
		return false
	}
	// Check RTP version (must be 2)
	if data[0]>>6 != 2 {
		return false
	}
	cc := int(data[0] & 0x0f)
	headerLen := 12 + (cc * 4)
	if len(data) < headerLen {
		return false
	}
	// skip RTCP packet types (200-204)
	if data[1] >= 200 && data[1] <= 204 {
		return false
	}
	return true
}
