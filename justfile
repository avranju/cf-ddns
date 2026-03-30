# Build the release binary
build:
    cargo build --release

# Run tests
test:
    cargo test

# Install the binary and systemd service unit file
install: build
    sudo install -Dm755 target/release/cf-ddns /usr/local/bin/cf-ddns
    sudo install -Dm644 cf-ddns-ipv6.service /etc/systemd/system/cf-ddns-ipv6.service
    sudo systemctl daemon-reload
    @echo "Installed. Run 'just enable' to enable and start the service."

# Enable and start the systemd service
enable:
    sudo systemctl enable --now cf-ddns-ipv6.service

# Disable and stop the systemd service
disable:
    sudo systemctl disable --now cf-ddns-ipv6.service
