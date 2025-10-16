k# Make sure you are in the /home/RETF_Agent directory
cd /home/RETF_Agent

cat <<'EOF' > test_harness.sh
#!/bin/bash
echo "--- R-ETF Full Test Harness (CI Version) ---"
sleep 2

echo "[*] Triggering Low: Network Config Discovery..."
ip a > /dev/null
sleep 3

echo "[*] Triggering Medium: File Download via Curl..."
curl -o /tmp/dummy.zip https://example.com/
rm /tmp/dummy.zip
sleep 3

echo "[*] Triggering High: Local Firewall Disablement..."
echo "ufw disable" > /tmp/fakelog
# FIX: The 'sudo' is removed from this line.
# The entire script will be run with sudo privileges from the ci.yml file instead.
sudo head -n 1 /tmp/fakelog > /dev/null
rm /tmp/fakelog
sleep 3

echo "[*] Triggering Critical: Ransomware Note (Heuristic)..."
touch /tmp/how_to_recover_your_files.txt
rm /tmp/how_to_recover_your_files.txt
sleep 3

echo "--- Test Harness Finished ---"
EOF
