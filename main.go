package main

import (
	"fmt"
	"log"

	flag "github.com/spf13/pflag"
)

var (
	Revision string
	Build    string
)

func main() {
	device := flag.StringP("device", "d", "", "Live capture interface")
	outputDir := flag.StringP("output", "o", "pcap", "Output directory for per-dialog pcap files")
	fromFilter := flag.StringP("from", "f", "", "Filter by caller number (partial match)")
	toFilter := flag.StringP("to", "t", "", "Filter by callee number (partial match)")
	bpfFilter := flag.StringP("bpf", "b", "", "BPF filter expression")
	debug := flag.BoolP("debug", "D", false, "Enable debug output")
	version := flag.BoolP("version", "v", false, "Print version and exit")
	flag.Parse()

	if *version {
		fmt.Printf("hepex %s (built %s)\n", Revision, Build)
		return
	}

	if *device == "" {
		log.Fatal("--device is required")
	}

	log.Printf("Starting live capture on interface %s", *device)
	if err := runLiveCapture(*device, *bpfFilter, *outputDir, *fromFilter, *toFilter, *debug); err != nil {
		log.Fatalf("Failed to capture live traffic: %v", err)
	}
}

func runLiveCapture(iface, bpfFilter, outputDir, fromFilter, toFilter string, debug bool) error {
	handle, source, err := openLiveSource(iface, bpfFilter)
	if err != nil {
		return err
	}
	defer handle.Close()

	tracker := NewDialogTracker()
	writer, err := NewDialogWriter(outputDir, true)
	if err != nil {
		return err
	}
	defer writer.Close()

	processor := NewLiveProcessor(tracker, writer, fromFilter, toFilter, debug)

	packetCount := 0
	for packet := range source.Packets() {
		packetCount++
		pkt := parsePacket(packet)
		if pkt == nil {
			continue
		}
		if err := processor.ProcessPacket(pkt); err != nil {
			return err
		}
	}

	log.Printf("Live capture ended, processed %d packets", packetCount)
	if processor.sipWritten == 0 {
		return fmt.Errorf("no HEP SIP packets found, check interface or BPF filter")
	}

	if debug {
		log.Printf("Dropped: %d SIP packets (early), %d RTP packets (early)", processor.sipDropped, processor.rtpDropped)
		log.Printf("RTP packets not matching any dialog: %d", processor.rtpUnmatched)
	}
	log.Printf("Written: %d SIP packets, %d RTP packets (%d decrypted, %d failed)",
		processor.sipWritten, processor.rtpWritten, processor.rtpDecrypted, processor.rtpDecryptFailed)
	log.Printf("Output files in: %s", outputDir)

	return nil
}
