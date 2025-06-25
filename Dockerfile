# Use the official Golang image to build the application
# Using golang:1.24.4-bookworm for the builder stage (latest stable Go on Bookworm base)
FROM golang:1.24.4-bookworm AS builder

# Set working directory
WORKDIR /app

# Copy the Go modules files and download dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy the source code
COPY main.go ./

# Build the application
# CGO_ENABLED=0 is important for static binaries (distroless compatibility)
# -o specifies the output binary name
RUN CGO_ENABLED=0 go build -a -installsuffix cgo -o custom-jwt-issuer .

# Use a minimal image for the final stage
# gcr.io/distroless/static-debian11 is compatible with bookworm/bullseye bases
FROM gcr.io/distroless/static-debian11

# Set the working directory
WORKDIR /app

# Copy the built binary from the builder stage
COPY --from=builder /app/custom-jwt-issuer .

# Expose the port
EXPOSE 8080

# Environment variables for configuration (defaults for the app)
ENV LISTEN_PORT="8080"
ENV JWT_ISSUER="https://my-go-issuer.example.com"
ENV JWT_AUDIENCE="your-api-audience"
ENV JWKS_ALG="RS512"
ENV JWKS_KID=""

# Command to run the application (in HTTP server mode)
CMD ["/app/custom-jwt-issuer"]

