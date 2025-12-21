package main

import (
	"fmt"
	"log"
	"net"
	"strings"

	flag "github.com/spf13/pflag"
)

var (
	Revision string
	Build    string
)

func main() {
	inputFile := flag.StringP("input", "i", "", "Input pcap file containing HEP traffic")
	outputDir := flag.StringP("output", "o", "pcap", "Output directory for per-dialog pcap files")
	fromFilter := flag.StringP("from", "f", "", "Filter by caller number (partial match)")
	toFilter := flag.StringP("to", "t", "", "Filter by callee number (partial match)")
	hepPort := flag.UintP("hep-port", "p", 9060, "HEP capture port")
	debug := flag.BoolP("debug", "d", false, "Enable debug output")
	version := flag.BoolP("version", "v", false, "Print version and exit")
	flag.Parse()

	if *version {
		fmt.Printf("hepex %s (built %s)\n", Revision, Build)
		return
	}

	log.Println("Reading pcap file...")

	reader, err := NewReader(*inputFile, uint16(*hepPort))
	if err != nil {
		log.Fatalf("Failed to open pcap: %v", err)
	}

	// First pass: Analyze HEP packets and build dialog map from SIP
	log.Println("Pass 1: Analyzing HEP packets and building dialog map...")
	tracker := NewDialogTracker()

	packetCount := 0
	hepCount := 0
	protocolCounts := make(map[string]int)
	tlsCounts := make(map[bool]int)
	sipCount := 0
	udpCount := 0

	err = reader.ForEach(func(pkt *Packet) error {
		packetCount++
		if pkt.IsUDP && !pkt.IsHEP {
			udpCount++
		}

		if !pkt.IsHEP || len(pkt.HEPPayload) == 0 {
			return nil
		}

		hepPkt, err := ParseHEP(pkt.HEPPayload)
		if err != nil {
			if *debug {
				log.Printf("Failed to parse HEP: %v", err)
			}
			return nil
		}

		hepCount++
		protocolCounts[hepPkt.ProtocolTypeName()]++
		tlsCounts[hepPkt.IsTLS()]++

		// Apply TLS filter for SIP (Note: in this capture TLS metadata may not be present)
		// We process all SIP to build dialog map
		if hepPkt.IsSIP() && len(hepPkt.Payload) > 0 {
			sipMsg, err := ParseSIP(hepPkt.Payload)
			if err == nil && sipMsg != nil {
				tracker.ProcessSIPMessage(sipMsg, hepPkt.Timestamp)
				sipCount++
			}
		}
		return nil
	})
	reader.Close()
	if err != nil {
		log.Fatalf("Failed to read packets: %v", err)
	}

	log.Printf("Read %d packets from pcap", packetCount)

	log.Printf("HEP packets: %d", hepCount)
	log.Printf("Protocol types:")
	for proto, count := range protocolCounts {
		log.Printf("  %s: %d", proto, count)
	}
	log.Printf("Transport: TCP/TLS=%d, UDP=%d", tlsCounts[true], tlsCounts[false])
	log.Printf("Raw UDP packets (non-HEP): %d", udpCount)
	log.Printf("Parsed %d SIP messages", sipCount)

	allDialogs := tracker.GetAllDialogs()
	log.Printf("Found %d dialogs total", len(allDialogs))

	// Filter dialogs: must have crypto + match from/to filters
	var dialogs []*Dialog
	cryptoDialogs := 0
	for _, d := range allDialogs {
		if !d.HasCrypto() {
			continue
		}
		cryptoDialogs++

		if *fromFilter != "" && !strings.Contains(d.FromUser, *fromFilter) {
			continue
		}

		if *toFilter != "" && !strings.Contains(d.ToUser, *toFilter) {
			continue
		}

		dialogs = append(dialogs, d)
	}

	log.Printf("Dialogs with SRTP crypto: %d", cryptoDialogs)
	if *fromFilter != "" || *toFilter != "" {
		log.Printf("Filters: from=%q to=%q", *fromFilter, *toFilter)
	}
	log.Printf("Processing %d dialogs", len(dialogs))

	if len(dialogs) == 0 {
		log.Println("No dialogs to process, nothing to output")
		return
	}

	for _, d := range dialogs {
		log.Printf("Dialog: %s -> %s (Call-ID: %s, streams: %d, crypto: %v)",
			d.FromUser, d.ToUser, truncate(d.CallID, 16), len(d.MediaStreams), d.HasCrypto())
		if *debug {
			for _, ms := range d.MediaStreams {
				log.Printf("  Media: %s %s:%d (crypto: %s, key: %d bytes)",
					ms.MediaType, ms.LocalIP, ms.LocalPort, ms.CryptoSuite, len(ms.MasterKey))
			}
		}
	}

	// Create SRTP contexts for each media stream
	srtpContexts := make(map[string]*SRTPContext)
	for _, d := range dialogs {
		for _, ms := range d.MediaStreams {
			if len(ms.MasterKey) > 0 && len(ms.MasterSalt) > 0 {
				key := fmt.Sprintf("%s:%d", ms.LocalIP, ms.LocalPort)
				if _, exists := srtpContexts[key]; exists {
					continue
				}
				ctx, err := NewSRTPContext(ms.MasterKey, ms.MasterSalt)
				if err != nil {
					log.Printf("Warning: failed to create SRTP context for %s: %v", key, err)
					continue
				}
				srtpContexts[key] = ctx
				if *debug {
					log.Printf("SRTP context for %s: masterKey=%x masterSalt=%x",
						key, ms.MasterKey, ms.MasterSalt)
				}
			}
		}
	}
	log.Printf("Created %d SRTP contexts", len(srtpContexts))

	// Build a set of valid dialog Call-IDs for filtering
	validDialogs := make(map[string]bool)
	for _, d := range dialogs {
		validDialogs[d.CallID] = true
	}

	// Second pass: Write packets to per-dialog pcap files
	log.Println("Pass 2: Writing per-dialog pcap files...")

	reader, err = NewReader(*inputFile, uint16(*hepPort))
	if err != nil {
		log.Fatalf("Failed to reopen pcap: %v", err)
	}

	writer, err := NewDialogWriter(*outputDir, true)
	if err != nil {
		log.Fatalf("Failed to create writer: %v", err)
	}
	defer writer.Close()

	sipWritten := 0
	rtpWritten := 0
	rtpDecrypted := 0
	rtpDecryptFailed := 0
	rtpUnmatched := 0

	err = reader.ForEach(func(pkt *Packet) error {
		// Process HEP-encapsulated SIP
		if pkt.IsHEP && len(pkt.HEPPayload) > 0 {
			hepPkt, err := ParseHEP(pkt.HEPPayload)
			if err != nil {
				return nil
			}

			if hepPkt.IsSIP() && len(hepPkt.Payload) > 0 {
				sipMsg, err := ParseSIP(hepPkt.Payload)
				if err != nil || sipMsg == nil {
					return nil
				}

				// Check if this dialog is in our filtered list
				if !validDialogs[sipMsg.CallID] {
					return nil
				}

				dialog := tracker.FindDialogByCallID(sipMsg.CallID)
				if dialog == nil {
					return nil
				}

				filename := dialog.Filename()
				err = writer.WriteSIPPacket(
					filename,
					hepPkt.Payload,
					hepPkt.SrcIP, hepPkt.DstIP,
					hepPkt.SrcPort, hepPkt.DstPort,
					hepPkt.Timestamp,
				)
				if err != nil {
					log.Printf("Warning: failed to write SIP packet: %v", err)
				} else {
					sipWritten++
				}
			}
			return nil
		}

		// Process raw UDP packets for SRTP/RTP
		if pkt.IsUDP && len(pkt.UDPPayload) > 0 && !pkt.IsHEP {
			if !IsRTPPacket(pkt.UDPPayload) {
				return nil
			}

			srcIP := net.ParseIP(pkt.SrcIP)
			dstIP := net.ParseIP(pkt.DstIP)

			dialog := tracker.FindDialogForMedia(
				srcIP, int(pkt.SrcPort),
				dstIP, int(pkt.DstPort),
			)
			if dialog == nil {
				rtpUnmatched++
				return nil
			}

			if !validDialogs[dialog.CallID] {
				return nil
			}

			filename := dialog.Filename()
			rtpPayload := pkt.UDPPayload

			// Try to decrypt SRTP
			srcKey := fmt.Sprintf("%s:%d", pkt.SrcIP, pkt.SrcPort)
			dstKey := fmt.Sprintf("%s:%d", pkt.DstIP, pkt.DstPort)

			var ctx *SRTPContext
			if c, ok := srtpContexts[srcKey]; ok {
				ctx = c
			} else if c, ok := srtpContexts[dstKey]; ok {
				ctx = c
			}

			if ctx != nil {
				decrypted, err := ctx.DecryptRTP(rtpPayload)
				if err == nil {
					rtpPayload = decrypted
					rtpDecrypted++
				} else {
					rtpDecryptFailed++
				}
			}

			err = writer.WriteRTPPacket(
				filename,
				rtpPayload,
				srcIP, dstIP,
				pkt.SrcPort, pkt.DstPort,
				pkt.Timestamp,
			)
			if err != nil {
				log.Printf("Warning: failed to write RTP packet: %v", err)
			} else {
				rtpWritten++
			}
		}
		return nil
	})
	reader.Close()
	if err != nil {
		log.Fatalf("Failed to read packets: %v", err)
	}

	if *debug {
		log.Printf("RTP packets not matching any dialog: %d", rtpUnmatched)
	}

	log.Printf("Written: %d SIP packets, %d RTP packets (%d decrypted, %d failed)", sipWritten, rtpWritten, rtpDecrypted, rtpDecryptFailed)
	log.Printf("Output files in: %s", *outputDir)

	// List output files
	for _, d := range dialogs {
		log.Printf("  %s", d.Filename())
	}
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
