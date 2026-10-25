#!/data/data/com.termux/files/usr/bin/bash
# Works in Termux; on Linux, run with bash install.sh if the shebang path differs.
set -eu
echo "Preparing SME Website Security Audit..."
if command -v pkg >/dev/null 2>&1; then
  pkg update
  pkg install -y python curl git
else
  echo "Termux pkg not found. Ensure Python 3 and Git are installed on this system."
fi
mkdir -p reports evidence capstone lab
python --version
echo "Setup complete. Run: python audit.py http://127.0.0.1:8080"
echo "Only audit systems you own or have explicit permission to test."
