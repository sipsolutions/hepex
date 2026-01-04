package main

import (
	"encoding/base64"
	"regexp"
	"strconv"
	"strings"
)

// SIPMessage represents a parsed SIP message
type SIPMessage struct {
	IsRequest  bool
	Method     string
	StatusCode int
	CallID     string
	FromTag    string
	FromUser   string
	ToTag      string
	ToUser     string
	SDP        *SDP
}

// SDP represents parsed SDP content
type SDP struct {
	Connection *SDPConnection
	Media      []SDPMedia
}

// SDPConnection represents c= line
type SDPConnection struct {
	Address string
}

// SDPMedia represents m= line and associated attributes
type SDPMedia struct {
	Type       string // audio, video
	Port       int
	Connection *SDPConnection
	Crypto     []SDPCrypto
	RTCP       int
}

// SDPCrypto represents a=crypto line for SDES
type SDPCrypto struct {
	CryptoSuite string // AES_CM_128_HMAC_SHA1_80
	MasterKey   []byte // decoded key
	MasterSalt  []byte // decoded salt
}

var (
	sipRequestLine  = regexp.MustCompile(`^([A-Z]+)\s+`)
	sipResponseLine = regexp.MustCompile(`^SIP/2\.0\s+(\d+)`)
	fromToTag       = regexp.MustCompile(`tag=([^;>\s]+)`)
	userFromURI     = regexp.MustCompile(`sip:([^@]+)@`)
	cryptoLine      = regexp.MustCompile(`^(\d+)\s+(\S+)\s+inline:([^\s|]+)`)
)

// ParseSIP parses a SIP message from raw bytes
func ParseSIP(data []byte) (*SIPMessage, error) {
	msg := &SIPMessage{}

	text := string(data)
	lines := strings.Split(text, "\r\n")
	if len(lines) == 0 {
		return nil, nil
	}

	firstLine := lines[0]
	if matches := sipRequestLine.FindStringSubmatch(firstLine); matches != nil {
		msg.IsRequest = true
		msg.Method = matches[1]
	} else if matches := sipResponseLine.FindStringSubmatch(firstLine); matches != nil {
		msg.IsRequest = false
		msg.StatusCode, _ = strconv.Atoi(matches[1])
	}

	var bodyStart int
	var contentType string
	for i := 1; i < len(lines); i++ {
		line := lines[i]
		if line == "" {
			bodyStart = i + 1
			break
		}

		if strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") {
			continue
		}

		colonIdx := strings.Index(line, ":")
		if colonIdx < 0 {
			continue
		}

		name := strings.ToLower(strings.TrimSpace(line[:colonIdx]))
		value := strings.TrimSpace(line[colonIdx+1:])

		switch name {
		case "call-id", "i":
			msg.CallID = value
		case "from", "f":
			msg.FromTag, msg.FromUser = parseFromTo(value)
		case "to", "t":
			msg.ToTag, msg.ToUser = parseFromTo(value)
		case "content-type", "c":
			contentType = value
		}
	}

	if bodyStart > 0 && bodyStart < len(lines) {
		if strings.Contains(strings.ToLower(contentType), "application/sdp") {
			body := strings.Join(lines[bodyStart:], "\r\n")
			msg.SDP = parseSDP(body)
		}
	}

	return msg, nil
}

func parseFromTo(value string) (tag, user string) {
	if matches := fromToTag.FindStringSubmatch(value); matches != nil {
		tag = matches[1]
	}
	if matches := userFromURI.FindStringSubmatch(value); matches != nil {
		user = matches[1]
	}
	return
}

func parseSDP(body string) *SDP {
	sdp := &SDP{}

	lines := strings.Split(body, "\r\n")

	var currentMedia *SDPMedia

	for _, line := range lines {
		if len(line) < 2 || line[1] != '=' {
			continue
		}

		typeChar := line[0]
		value := line[2:]

		switch typeChar {
		case 'c':
			conn := parseConnection(value)
			if currentMedia != nil {
				currentMedia.Connection = conn
			} else {
				sdp.Connection = conn
			}
		case 'm':
			media := parseMediaLine(value)
			sdp.Media = append(sdp.Media, media)
			currentMedia = &sdp.Media[len(sdp.Media)-1]
		case 'a':
			if currentMedia != nil {
				parseAttribute(value, currentMedia)
			}
		}
	}

	return sdp
}

func parseConnection(value string) *SDPConnection {
	parts := strings.Fields(value)
	if len(parts) < 3 {
		return nil
	}
	return &SDPConnection{Address: parts[2]}
}

func parseMediaLine(value string) SDPMedia {
	media := SDPMedia{}
	parts := strings.Fields(value)
	if len(parts) >= 2 {
		media.Type = parts[0]
		media.Port, _ = strconv.Atoi(parts[1])
	}
	return media
}

func parseAttribute(value string, media *SDPMedia) {
	colonIdx := strings.Index(value, ":")
	if colonIdx < 0 {
		return
	}
	attrName := value[:colonIdx]
	attrValue := value[colonIdx+1:]

	switch attrName {
	case "crypto":
		crypto := parseCryptoLine(attrValue)
		if crypto != nil {
			media.Crypto = append(media.Crypto, *crypto)
		}
	case "rtcp":
		parts := strings.Fields(attrValue)
		if len(parts) >= 1 {
			if port, err := strconv.Atoi(parts[0]); err == nil {
				media.RTCP = port
			}
		}
	}
}

func parseCryptoLine(value string) *SDPCrypto {
	matches := cryptoLine.FindStringSubmatch(value)
	if matches == nil {
		return nil
	}

	crypto := &SDPCrypto{CryptoSuite: matches[2]}

	// Decode the key material (key:salt concatenated, base64 encoded)
	// For AES_CM_128_HMAC_SHA1_80: 16 bytes key + 14 bytes salt = 30 bytes
	keyMaterial, err := base64.StdEncoding.DecodeString(matches[3])
	if err == nil && len(keyMaterial) >= 30 {
		crypto.MasterKey = keyMaterial[:16]
		crypto.MasterSalt = keyMaterial[16:30]
	}

	return crypto
}
