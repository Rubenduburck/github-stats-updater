#!/bin/bash

echo "GitHub Stats Updater - Raspberry Pi Setup"
echo "=========================================="

if [ -z "$GITHUB_TOKEN" ]; then
    echo "Please set your GitHub Personal Access Token:"
    echo "export GITHUB_TOKEN='your_token_here'"
    echo ""
    echo "Create a token at: https://github.com/settings/tokens"
    echo "Required scopes: repo (all), read:user"
    exit 1
fi

echo "Building release binary for ARM..."
cargo build --release

echo ""
echo "Binary built at: ./target/release/github-stats-updater"
echo ""
echo "To run manually:"
echo "  GITHUB_TOKEN=$GITHUB_TOKEN ./target/release/github-stats-updater"
echo ""
echo "To set up automatic updates (cron):"
echo "  1. Run: crontab -e"
echo "  2. Add this line to run every 6 hours:"
echo "     0 */6 * * * GITHUB_TOKEN=$GITHUB_TOKEN /home/pi/github-stats-updater/target/release/github-stats-updater"
echo ""
echo "For systemd timer (alternative to cron):"
echo "  See github-stats-updater.service and github-stats-updater.timer files"