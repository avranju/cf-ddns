# Stage 1: Build the Rust application
FROM rust:slim-bookworm AS builder

WORKDIR /app

# Copy Rust project files
COPY Cargo.toml Cargo.lock ./
COPY src ./src/

# Build the release binary
RUN cargo build --release

# Stage 3: Create the final image
FROM debian:bookworm-slim

# Install root certificates
RUN apt-get update
RUN apt install -y ca-certificates

WORKDIR /app

# Copy the compiled executable from the builder stage
COPY --from=builder /app/target/release/cf-ddns /app/cf-ddns

# Set the entrypoint to run the application
ENTRYPOINT ["/app/cf-ddns"]
