# hepex

Builds per-dialog pcap files from HEP SIP and SRTP captures. Decrypts the SRTP based on SDES key in SIP SDP payload.

Streams packets directly from the network interface.

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

```
./hepex -d any -b 'udp and (port 9060 or portrange 40000-50000)'
```

Filters:

```
./hepex -d any --from 1001 --to 1002
```

## Options

- `-d, --device` Live capture interface (required)
- `-o, --output` Output directory for per-dialog pcaps (default: pcap)
- `-f, --from` Filter by caller number (partial match)
- `-t, --to` Filter by callee number (partial match)
- `-b, --bpf` BPF filter expression for capture
- `-D, --debug` Enable debug output
- `-v, --version` Print version and exit

HEP packets are auto-detected by the `HEP3` header.
