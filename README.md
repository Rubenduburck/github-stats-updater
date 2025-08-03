# GitHub Stats Updater

Automatically updates your GitHub profile README with lines of code statistics from all your repositories (public and private).

## Features

- Counts lines of code across all your GitHub repositories
- Includes both public and private repositories
- Groups statistics by programming language
- Automatically commits and pushes updates to your profile repository
- Lightweight Rust implementation perfect for Raspberry Pi

## Setup

### 1. Create GitHub Personal Access Token

Go to https://github.com/settings/tokens and create a token with:
- `repo` scope (all checkboxes)
- `read:user` scope

### 2. Build for Raspberry Pi

```bash
# On your development machine (cross-compile for ARM)
cargo build --release --target armv7-unknown-linux-gnueabihf

# Or build directly on Raspberry Pi
cargo build --release
```

### 3. Deploy to Raspberry Pi

```bash
# Copy to your Raspberry Pi
scp -r github-stats-updater/ pi@raspberrypi:/home/pi/

# SSH into your Pi
ssh pi@raspberrypi

# Set up environment variable
export GITHUB_TOKEN="your_token_here"

# Test run
./github-stats-updater/target/release/github-stats-updater
```

### 4. Set Up Automatic Updates

#### Option A: Using Cron
```bash
crontab -e
# Add this line to run every 6 hours:
0 */6 * * * GITHUB_TOKEN=your_token_here /home/pi/github-stats-updater/target/release/github-stats-updater
```

#### Option B: Using systemd
```bash
# Copy service files
sudo cp github-stats-updater.service /etc/systemd/system/
sudo cp github-stats-updater.timer /etc/systemd/system/

# Edit the service file to add your token
sudo nano /etc/systemd/system/github-stats-updater.service
# Replace YOUR_TOKEN_HERE with your actual token

# Enable and start the timer
sudo systemctl daemon-reload
sudo systemctl enable github-stats-updater.timer
sudo systemctl start github-stats-updater.timer

# Check status
sudo systemctl status github-stats-updater.timer
```

## Configuration

The updater accepts these command-line arguments:

- `--token` or `-t`: GitHub personal access token (can also use GITHUB_TOKEN env var)
- `--username` or `-u`: GitHub username (default: rubenduburck)
- `--repo-name` or `-r`: Profile repository name (default: rubenduburck)
- `--readme-path`: Path to README file in the repository (default: README.md)

## Cross-Compilation for Raspberry Pi

If compiling on a different machine:

```bash
# Install cross-compilation tools
rustup target add armv7-unknown-linux-gnueabihf

# Build
cargo build --release --target armv7-unknown-linux-gnueabihf
```

## Troubleshooting

- **SSL/OpenSSL errors**: The Cargo.toml is configured to use HTTPS without SSH dependencies to avoid OpenSSL issues
- **Authentication failures**: Make sure your token has the correct scopes
- **Push failures**: Ensure your profile repository exists and the token has write access