package main

import (
	"fmt"
	"hash/fnv"
	"net"
	"strings"
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
	FromUser     string
	ToUser       string
	StartTime    time.Time
	LastSeen     time.Time
	MediaStreams []MediaStream
	MediaKeys    []string
	ContextKeys  []string
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

	timestamp := d.StartTime.Format("20060102T150405")
	return fmt.Sprintf("%s_%s_%s_%s.pcap", timestamp, fromUser, toUser, d.fileSuffix())
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

func (d *Dialog) fileSuffix() string {
	suffix := sanitizeFilename(d.CallID)
	if suffix != "" {
		return suffix
	}

	hasher := fnv.New32a()
	_, _ = hasher.Write([]byte(d.CallID))
	return fmt.Sprintf("%08x", hasher.Sum32())
}

func (d *Dialog) MatchesFilters(fromFilter, toFilter string) bool {
	if d == nil {
		return false
	}
	if fromFilter != "" && !strings.Contains(d.FromUser, fromFilter) {
		return false
	}
	if toFilter != "" && !strings.Contains(d.ToUser, toFilter) {
		return false
	}
	return true
}

// DialogTracker manages SIP dialogs and maps media streams to them
type DialogTracker struct {
	sync.RWMutex
	dialogsByCallID map[string]*Dialog
	mediaToDialog   map[string]*Dialog
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

	dialog := dt.upsertDialog(msg, timestamp)
	if dialog == nil {
		return nil
	}

	dialog.LastSeen = timestamp

	if msg.SDP != nil {
		dt.replaceDialogMedia(dialog, msg.SDP)
	}

	return dialog
}

func (dt *DialogTracker) upsertDialog(msg *SIPMessage, timestamp time.Time) *Dialog {
	if msg.CallID == "" {
		return nil
	}

	if dialog, ok := dt.dialogsByCallID[msg.CallID]; ok {
		dt.updateDialogMetadata(dialog, msg)
		return dialog
	}

	dialog := newDialogFromMessage(msg, timestamp)
	dt.dialogsByCallID[msg.CallID] = dialog
	return dialog
}

func newDialogFromMessage(msg *SIPMessage, timestamp time.Time) *Dialog {
	return &Dialog{
		CallID:    msg.CallID,
		FromUser:  msg.FromUser,
		ToUser:    msg.ToUser,
		StartTime: timestamp,
		LastSeen:  timestamp,
	}
}

func (dt *DialogTracker) updateDialogMetadata(dialog *Dialog, msg *SIPMessage) {
	if dialog.FromUser == "" {
		dialog.FromUser = msg.FromUser
	}
	if dialog.ToUser == "" {
		dialog.ToUser = msg.ToUser
	}
}

func (dt *DialogTracker) replaceDialogMedia(dialog *Dialog, sdp *SDP) {
	dt.unmapDialogMedia(dialog)

	streams := make([]MediaStream, 0, len(sdp.Media))
	mediaKeys := make([]string, 0, len(sdp.Media)*2)
	sessionConn := sdp.Connection

	for _, media := range sdp.Media {
		if media.Port == 0 {
			continue
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
		if len(media.Crypto) > 0 {
			crypto := media.Crypto[0]
			stream.CryptoSuite = crypto.CryptoSuite
			stream.MasterKey = crypto.MasterKey
			stream.MasterSalt = crypto.MasterSalt
		}

		streams = append(streams, stream)

		rtpKey := mediaAddressKey(conn.Address, media.Port)
		dt.mediaToDialog[rtpKey] = dialog
		mediaKeys = append(mediaKeys, rtpKey)

		rtcpPort := media.Port + 1
		if media.RTCP != 0 {
			rtcpPort = media.RTCP
		}
		rtcpKey := mediaAddressKey(conn.Address, rtcpPort)
		dt.mediaToDialog[rtcpKey] = dialog
		mediaKeys = append(mediaKeys, rtcpKey)
	}

	dialog.MediaStreams = streams
	dialog.MediaKeys = mediaKeys
}

func (dt *DialogTracker) unmapDialogMedia(dialog *Dialog) {
	for _, key := range dialog.MediaKeys {
		if dt.mediaToDialog[key] == dialog {
			delete(dt.mediaToDialog, key)
		}
	}
	dialog.MediaStreams = nil
	dialog.MediaKeys = nil
}

func (dt *DialogTracker) PruneExpired(now time.Time, maxIdle time.Duration) []*Dialog {
	dt.Lock()
	defer dt.Unlock()

	var expired []*Dialog

	for key, dialog := range dt.dialogsByCallID {
		if now.Sub(dialog.LastSeen) <= maxIdle {
			continue
		}
		dt.unmapDialogMedia(dialog)
		delete(dt.dialogsByCallID, key)
		expired = append(expired, dialog)
	}

	return expired
}

func mediaAddressKey(address string, port int) string {
	return fmt.Sprintf("%s:%d", address, port)
}

// FindDialogForMedia finds the dialog associated with an RTP/RTCP stream
func (dt *DialogTracker) FindDialogForMedia(srcIP net.IP, srcPort int, dstIP net.IP, dstPort int) *Dialog {
	dt.RLock()
	defer dt.RUnlock()

	srcKey := mediaAddressKey(srcIP.String(), srcPort)
	if dialog, ok := dt.mediaToDialog[srcKey]; ok {
		return dialog
	}

	dstKey := mediaAddressKey(dstIP.String(), dstPort)
	if dialog, ok := dt.mediaToDialog[dstKey]; ok {
		return dialog
	}

	return nil
}
