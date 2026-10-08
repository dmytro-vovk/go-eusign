ROOT := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
LINUX_LIB := $(ROOT)src/lib/linux/$(if $(filter aarch64 arm64,$(shell uname -m)),arm,$(if $(filter i386 i686,$(shell uname -m)),32,64))

.PHONY:
run:
	LD_LIBRARY_PATH=$(LINUX_LIB) DYLD_LIBRARY_PATH=$(ROOT)src/lib/darwin go run cmd/test.go

.PHONY:
test:
	LD_LIBRARY_PATH=$(LINUX_LIB) DYLD_LIBRARY_PATH=$(ROOT)src/lib/darwin go test -race -count=3 ./...

.PHONY:
lint:
	@go mod tidy
	@golangci-lint run

build:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=1 go build ./...

.PHONY:
refresh:
	@wget https://iit.com.ua/download/productfiles/CACertificates.p7b -O data/CACertificates.p7b
	@wget https://iit.com.ua/download/productfiles/CACertificates.Test.All.p7b -O data/CACertificates.Test.All.p7b
	@wget https://iit.com.ua/download/productfiles/CAs.json -O data/CAs.json
