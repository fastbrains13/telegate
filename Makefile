.PHONY: build test docker-run clean

build:
	CGO_ENABLED=0 go build -o bin/panel ./cmd/panel
	CGO_ENABLED=0 go build -o bin/agent ./cmd/agent

test:
	go test -v ./...

docker-run:
	docker compose -f docker/docker-compose.yml up -d --build

clean:
	rm -rf bin/
