.PHONY: all linux windows test docker clean

GO ?= go
BINDIR := bin

all: linux

linux:
	@mkdir -p $(BINDIR)
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 $(GO) build -o $(BINDIR)/hw2api -buildvcs=false ./cmd/server
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 $(GO) build -o $(BINDIR)/hw2api-login -buildvcs=false ./cmd/login
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 $(GO) build -o $(BINDIR)/hw2api-credit -buildvcs=false ./cmd/credit
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 $(GO) build -o $(BINDIR)/hw2api-apply -buildvcs=false ./cmd/apply
	@echo "linux binaries -> $(BINDIR)/"

windows:
	@mkdir -p $(BINDIR)
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 $(GO) build -o $(BINDIR)/hw2api.exe -buildvcs=false ./cmd/server
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 $(GO) build -o $(BINDIR)/hw2api-login.exe -buildvcs=false ./cmd/login
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 $(GO) build -o $(BINDIR)/hw2api-credit.exe -buildvcs=false ./cmd/credit
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 $(GO) build -o $(BINDIR)/hw2api-apply.exe -buildvcs=false ./cmd/apply
	@echo "windows binaries -> $(BINDIR)/"

test:
	$(GO) test ./...

docker:
	docker compose up -d --build

clean:
	rm -rf $(BINDIR) data
