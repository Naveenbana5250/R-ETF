#!/bin/bash
set -e # Exit immediately if a command fails

echo "--- R-ETF CI/CD Test Harness ---"

echo "[+] Triggering: System Information Discovery (low)"
whoami

echo "[+] Triggering: Script Execution from /tmp (medium)"
echo "#!/bin/bash\necho test" > /tmp/ci_test_script.sh
bash /tmp/ci_test_script.sh
rm /tmp/ci_test_script.sh

echo "[+] Triggering: Suspicious Process Execution: Netcat (high)"
# Start nc, wait 1 sec, then kill it.
nc -lp 4444 &
sleep 1
kill $!

echo "[+] Triggering: Password File Modification (critical)"
# This command will run with sudo from the CI file
touch /etc/passwd

echo "--- Test Harness Finished ---"
