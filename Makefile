# Makefile for custom-jwt-issuer

APP_NAME=custom-jwt-issuer
GO_FILES=$(shell find . -type f -name '*.go' -not -path "./vendor/*")

.PHONY: all build test clean fmt lint run docker-build docker-run

all: build

build:
	go build -o $(APP_NAME) main.go

run: build
	./$(APP_NAME)

test:
	go test -v ./...

cover:
	go test -cover ./...

cover-html:
	go test -coverprofile=coverage.out ./... && go tool cover -html=coverage.out

fmt:
	gofmt -w $(GO_FILES)

lint:
	golint ./...

clean:
	rm -f $(APP_NAME) coverage.out

# Generate keys and JWTs via CLI
keys:
	go run main.go generate-keys
jwt:
	go run main.go generate-jwt private_key.pem '{"sub":"cliuser"}'

docker-build:
	docker build -t custom-jwt-issuer:latest .

docker-run:
	docker run --rm -p 8080:8080 custom-jwt-issuer:latest
