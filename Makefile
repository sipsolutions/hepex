VERSION=$(shell git describe --tags --always --dirty 2>/dev/null || echo "")
BUILD=$(shell date '+%FT%T%z')

LDFLAGS=-ldflags "-X main.Revision=$(VERSION) -X main.Build=$(BUILD)"

build:
	go build $(LDFLAGS)

clean:
	go clean -i

test:
	go test -v

.PHONY: build clean test
