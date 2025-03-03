ROOT := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

.PHONY:
run:
	LD_LIBRARY_PATH=$(ROOT)internal/src/lib DYLD_LIBRARY_PATH=$(ROOT)internal/src/lib/darwin go run cmd/test.go

.PHONY:
test:
	LD_LIBRARY_PATH=$(ROOT)internal/src/lib/linux/64 DYLD_LIBRARY_PATH=$(ROOT)internal/src/lib/darwin go test -race -count=3 ./...

.PHONY:
lint:
	@go mod tidy
	@golangci-lint run

.PHONY:
refresh:
	@wget https://iit.com.ua/download/productfiles/CACertificates.p7b -O data/CACertificates.p7b
	@wget https://iit.com.ua/download/productfiles/CACertificates.Test.All.p7b -O data/CACertificates.Test.All.p7b
	@wget https://iit.com.ua/download/productfiles/CAs.json -O data/CAs.json
