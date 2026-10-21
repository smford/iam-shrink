BINARY_NAME=iam-shrink
BIN_DIR=bin
CMD_DIR=./cmd/iam-shrink

.PHONY: all build test vet clean install

all: build

build:
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 go build -ldflags="-s -w" -o $(BIN_DIR)/$(BINARY_NAME) $(CMD_DIR)

test:
	CGO_ENABLED=0 go test -v -race=false ./...

vet:
	go vet ./...

clean:
	rm -rf $(BIN_DIR)

install:
	CGO_ENABLED=0 go install $(CMD_DIR)
