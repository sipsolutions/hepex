# hepex

Builds per-dialog pcap files from HEP SIP and SRTP captures. Decrypts the SRTP based on SDES key in SIP SDP payload.

Live mode captures all traffic matching BPF filter into a temporary file before parsing, spplitting and decryption.

Supports only SRTP with SDES encryption.

## Build

```
make
```
or

```
go build
```

## Usage

Offline pcap:

```
./hepex -i input.pcap -o pcap
```

Live capture:

```
./hepex -i any -b 'udp and (port 9060 or portrange 40000-50000)'
```

Filters:

```
./hepex -i input.pcap --from 1001 --to 1002
```

## Options

- `-i, --input` Input pcap file or network interface
- `-o, --output` Output directory for per-dialog pcaps
- `-f, --from` Filter by caller number (partial match)
- `-t, --to` Filter by callee number (partial match)
- `-b, --bpf` BPF filter expression for capture
- `-d, --debug` Enable debug output
- `-v, --version` Print version and exit

HEP packets are auto-detected by the `HEP3` header; if none are found, the run exits with an error.
