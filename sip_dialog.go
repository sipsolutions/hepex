package main

import (
	"fmt"
	"net"
	"sync"
	"time"
)

// MediaStream represents an RTP/SRTP stream associated with a dialog
type MediaStream struct {
	LocalIP     net.IP
	LocalPort   int
	MediaType   string // audio, video
	CryptoSuite string
	MasterKey   []byte
	MasterSalt  []byte
}

// Dialog represents a SIP dialog
type Dialog struct {
	CallID       string
	FromTag      string
	ToTag        string
	FromUser     string
	ToUser       string
	StartTime    time.Time
	MediaStreams []MediaStream
}

// Filename returns the output filename for this dialog
func (d *Dialog) Filename() string {
	fromUser := sanitizeFilename(d.FromUser)
	toUser := sanitizeFilename(d.ToUser)
	if fromUser == "" {
		fromUser = "unknown"
	}
	if toUser == "" {
		toUser = "unknown"
	}
	// Format: YYYYmmddTHHMMSS
	timestamp := d.StartTime.Format("20060102T150405")
	return fmt.Sprintf("%s_%s_%s.pcap", timestamp, fromUser, toUser)
}

// HasCrypto returns true if any media stream has SRTP crypto keys
func (d *Dialog) HasCrypto() bool {
	for _, ms := range d.MediaStreams {
		if len(ms.MasterKey) > 0 && len(ms.MasterSalt) > 0 {
			return true
		}
	}
	return false
}

func sanitizeFilename(s string) string {
	result := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' {
			result = append(result, c)
		}
	}
	return string(result)
}

// DialogTracker manages SIP dialogs and maps media streams to them
type DialogTracker struct {
	sync.RWMutex
	// Map from Call-ID to Dialog
	dialogsByCallID map[string]*Dialog
	// Map from IP:port to Dialog for RTP correlation
	mediaToDialog map[string]*Dialog
}

// NewDialogTracker creates a new dialog tracker
func NewDialogTracker() *DialogTracker {
	return &DialogTracker{
		dialogsByCallID: make(map[string]*Dialog),
		mediaToDialog:   make(map[string]*Dialog),
	}
}

// ProcessSIPMessage processes a SIP message and updates dialog state
func (dt *DialogTracker) ProcessSIPMessage(msg *SIPMessage, timestamp time.Time) *Dialog {
	dt.Lock()
	defer dt.Unlock()

	dialog := dt.findOrCreateDialog(msg, timestamp)
	if dialog == nil {
		return nil
	}

	// Update To-tag from response
	if !msg.IsRequest && msg.StatusCode >= 200 && msg.StatusCode < 300 {
		if dialog.ToTag == "" && msg.ToTag != "" {
			dialog.ToTag = msg.ToTag
		}
	}

	// Extract media info from SDP
	if msg.SDP != nil {
		dt.extractMediaStreams(dialog, msg)
	}

	return dialog
}

func (dt *DialogTracker) findOrCreateDialog(msg *SIPMessage, timestamp time.Time) *Dialog {
	if msg.CallID == "" {
		return nil
	}

	dialog, exists := dt.dialogsByCallID[msg.CallID]
	if !exists {
		dialog = &Dialog{
			CallID:    msg.CallID,
			FromTag:   msg.FromTag,
			ToTag:     msg.ToTag,
			FromUser:  msg.FromUser,
			ToUser:    msg.ToUser,
			StartTime: timestamp,
		}
		dt.dialogsByCallID[msg.CallID] = dialog
	}

	if dialog.ToTag == "" && msg.ToTag != "" {
		dialog.ToTag = msg.ToTag
	}

	return dialog
}

func (dt *DialogTracker) extractMediaStreams(dialog *Dialog, msg *SIPMessage) {
	if msg.SDP == nil {
		return
	}

	// Get session-level connection if no media-level
	sessionConn := msg.SDP.Connection

	for _, media := range msg.SDP.Media {
		if media.Port == 0 {
			continue // disabled media
		}

		conn := media.Connection
		if conn == nil {
			conn = sessionConn
		}
		if conn == nil {
			continue
		}

		stream := MediaStream{
			LocalIP:   net.ParseIP(conn.Address),
			LocalPort: media.Port,
			MediaType: media.Type,
		}

		// Get crypto info
		if len(media.Crypto) > 0 {
			crypto := media.Crypto[0] // Use first crypto suite
			stream.CryptoSuite = crypto.CryptoSuite
			stream.MasterKey = crypto.MasterKey
			stream.MasterSalt = crypto.MasterSalt
		}

		// Add stream and map it
		dialog.MediaStreams = append(dialog.MediaStreams, stream)

		// Map this IP:port to the dialog
		key := fmt.Sprintf("%s:%d", conn.Address, media.Port)
		dt.mediaToDialog[key] = dialog

		// Also map RTCP port (RTP port + 1, unless specified)
		rtcpPort := media.Port + 1
		if media.RTCP != 0 {
			rtcpPort = media.RTCP
		}
		rtcpKey := fmt.Sprintf("%s:%d", conn.Address, rtcpPort)
		dt.mediaToDialog[rtcpKey] = dialog
	}
}

// FindDialogForMedia finds the dialog associated with an RTP/RTCP stream
func (dt *DialogTracker) FindDialogForMedia(srcIP net.IP, srcPort int, dstIP net.IP, dstPort int) *Dialog {
	dt.RLock()
	defer dt.RUnlock()

	// Try source IP:port
	srcKey := fmt.Sprintf("%s:%d", srcIP.String(), srcPort)
	if dialog, ok := dt.mediaToDialog[srcKey]; ok {
		return dialog
	}

	// Try destination IP:port
	dstKey := fmt.Sprintf("%s:%d", dstIP.String(), dstPort)
	if dialog, ok := dt.mediaToDialog[dstKey]; ok {
		return dialog
	}

	return nil
}

// FindDialogByCallID finds a dialog by Call-ID
func (dt *DialogTracker) FindDialogByCallID(callID string) *Dialog {
	dt.RLock()
	defer dt.RUnlock()
	return dt.dialogsByCallID[callID]
}

// GetAllDialogs returns all tracked dialogs
func (dt *DialogTracker) GetAllDialogs() []*Dialog {
	dt.RLock()
	defer dt.RUnlock()

	dialogs := make([]*Dialog, 0, len(dt.dialogsByCallID))
	for _, d := range dt.dialogsByCallID {
		dialogs = append(dialogs, d)
	}
	return dialogs
}
