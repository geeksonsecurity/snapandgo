GO111MODULE=on
GOBIN=$(shell pwd)/bin
VERSION := "0.1"
INSTALL_FLAG=-v -ldflags "-s -w"

all: build

build: 
		GOBIN=$(GOBIN) GO111MODULE=$(GO111MODULE) go install $(INSTALL_FLAG) $(VERSION_FLAG) ./...

clean:
				@rm -rf $(GOBIN)

.PHONY: build clean all
