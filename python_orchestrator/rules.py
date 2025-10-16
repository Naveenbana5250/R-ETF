RULES = [
    {
        "rule": "Suspicious Process Execution: Netcat",
        "description": "Execution of netcat (nc), often used for reverse shells, data transfer, or pivoting.",
        "severity": "high", "type": "Execution (T1059.004)", "logsource": "process_start",
        "detection": { "keywords": ["nc", "ncat", "netcat"], "field": "name" },
        "tags": ["attack.execution", "attack.command_and_control"]
    },
    {
        "rule": "System Information Discovery",
        "description": "Execution of common reconnaissance commands to gather system information.",
        "severity": "low", "type": "Discovery (T1082)", "logsource": "process_start",
        "detection": { "keywords": ["whoami", "hostname", "uname", "id", "pwd"], "field": "name" },
        "tags": ["attack.discovery"]
    },
    {
        "rule": "Script Execution from /tmp Directory",
        "description": "An interpreter (sh, bash, python) was used to run a script from the /tmp directory, a common location for malware.",
        "severity": "medium", "type": "Execution (T1059)", "logsource": "process_start",
        "detection": { "process_names": ["sh", "bash", "python", "python3", "perl", "php"], "command_substring": "/tmp/" },
        "tags": ["attack.execution", "attack.defense_evasion"]
    },
    {
        "rule": "Critical Credential File Access",
        "description": "Access to a highly sensitive system file or directory containing credentials.",
        "severity": "critical", "type": "Credential Access (T1003)", "logsource": "file_event",
        "detection": { "keywords": ["/etc/shadow", "/root/.ssh", "id_rsa", "known_hosts"], "field": "path" },
        "tags": ["attack.credential_access"]
    },
    {
        "rule": "Potential Log Tampering",
        "description": "A critical system log file was modified or deleted, possibly to hide malicious activity.",
        "severity": "medium", "type": "Defense Evasion (T1070.001)", "logsource": "file_event",
        "detection": { "keywords": ["/var/log/auth.log", "/var/log/syslog", "/var/log/wtmp"], "field": "path" },
        "tags": ["attack.defense_evasion"]
    },
    {
        "rule": "SSH Configuration File Modified",
        "description": "Modification of SSH configuration files, which could indicate an attempt to weaken security or install a backdoor.",
        "severity": "high", "type": "Persistence (T1556.001)", "logsource": "file_event",
        "detection": { "keywords": ["/etc/ssh/sshd_config"], "field": "path" },
        "tags": ["attack.persistence", "attack.defense_evasion"]
    },
    {
        "rule": "Outbound Connection to Common C2 Port",
        "description": "A network connection was made to a port commonly used for Command & Control (C2) channels.",
        "severity": "high", "type": "Command and Control (T1071)", "logsource": "network_conn",
        "detection": { "keywords": [":1337", ":4444", ":6666", ":8443"], "field": "remote_address" },
        "tags": ["attack.command_and_control"]
    },
    {
        "rule": "Network Configuration Discovery",
        "description": "Execution of 'ip' or 'ifconfig' to gather network interface information.",
        "severity": "low", "type": "Discovery (T1016)", "logsource": "process_start",
        "detection": { "keywords": ["ip a", "ifconfig"], "field": "cmd" },
        "tags": ["attack.discovery"]
    },
    {
        "rule": "Network Connection Discovery",
        "description": "Execution of 'netstat' to identify active network connections.",
        "severity": "low", "type": "Discovery (T1049)", "logsource": "process_start",
        "detection": { "keywords": ["netstat"], "field": "name" },
        "tags": ["attack.discovery"]
    },
    {
        "rule": "Local Firewall Disablement",
        "description": "An attempt to disable the Uncomplicated Firewall (UFW), a common defense evasion technique.",
        "severity": "high", "type": "Defense Evasion (T1562.004)", "logsource": "process_start",
        "detection": { "keywords": ["ufw disable"], "field": "cmd" },
        "tags": ["attack.defense_evasion"]
    },
    {
        "rule": "Crontab Interactive Management",
        "description": "Interactive management of cron jobs, which could indicate an attempt to establish persistence.",
        "severity": "medium", "type": "Persistence (T1053.003)", "logsource": "process_start",
        "detection": { "keywords": ["crontab -e", "crontab -r"], "field": "cmd" },
        "tags": ["attack.persistence", "attack.privilege_escalation"]
    },
    {
        "rule": "File Download via Wget/Curl",
        "description": "Use of wget or curl to download a file from a remote source.",
        "severity": "medium", "type": "Command and Control (T1105)", "logsource": "process_start",
        "detection": { "keywords": ["wget http", "curl -O", "curl -o"], "field": "cmd" },
        "tags": ["attack.command_and_control"]
    },
    {
        "rule": "Execution from Shared Memory",
        "description": "A process was executed from the /dev/shm directory, a common location for fileless malware.",
        "severity": "high", "type": "Defense Evasion (T1055)", "logsource": "process_start",
        "detection": { "process_names": [], "command_substring": "/dev/shm/" },
        "tags": ["attack.defense_evasion", "attack.execution"]
    },
    {
        "rule": "Base64 Encoded Command Execution",
        "description": "Use of base64 to decode a command and pipe it directly to a shell, a classic obfuscation technique.",
        "severity": "high", "type": "Defense Evasion (T1027)", "logsource": "process_start",
        "detection": { "keywords": ["base64 -d", "| sh", "| bash"], "field": "cmd" },
        "tags": ["attack.defense_evasion", "attack.execution"]
    },
    {
        "rule": "Sudo Permissions Discovery",
        "description": "Use of 'sudo -l' to check for the current user's available sudo privileges.",
        "severity": "low", "type": "Discovery (T1548.003)", "logsource": "process_start",
        "detection": { "keywords": ["sudo -l"], "field": "cmd" },
        "tags": ["attack.discovery", "attack.privilege_escalation"]
    },
    {
        "rule": "Dynamic Linker Hijacking (LD_PRELOAD)",
        "description": "A process was started with the LD_PRELOAD environment variable set, a technique to hijack library functions.",
        "severity": "high", "type": "Defense Evasion (T1574.006)", "logsource": "process_start",
        "detection": { "keywords": ["LD_PRELOAD="], "field": "cmd" },
        "tags": ["attack.defense_evasion", "attack.privilege_escalation", "attack.persistence"]
    },
    {
        "rule": "User Profile Script Modification",
        "description": "Modification of .bashrc or .profile, a common technique for establishing user-level persistence.",
        "severity": "medium", "type": "Persistence (T1546.004)", "logsource": "file_event",
        "detection": { "keywords": [".bashrc", ".profile"], "field": "path" },
        "tags": ["attack.persistence"]
    },
    {
        "rule": "New SSH Key Added",
        "description": "A new SSH key was added to authorized_keys, potentially allowing unauthorized remote access.",
        "severity": "high", "type": "Persistence (T1098.004)", "logsource": "file_event",
        "detection": { "keywords": ["authorized_keys"], "field": "path" },
        "tags": ["attack.persistence", "attack.credential_access"]
    },
    {
        "rule": "Command History File Cleared",
        "description": "An attempt to clear or overwrite the bash history file to hide executed commands.",
        "severity": "medium", "type": "Defense Evasion (T1070.003)", "logsource": "file_event",
        "detection": { "keywords": [".bash_history"], "field": "path" },
        "tags": ["attack.defense_evasion"]
    },
    {
        "rule": "Hidden Directory Creation in /tmp",
        "description": "Creation of a hidden directory (starting with a dot) in /tmp, a suspicious staging behavior.",
        "severity": "low", "type": "Defense Evasion (T1564.001)", "logsource": "file_event",
        "detection": { "keywords": ["/tmp/."], "field": "path" },
        "tags": ["attack.defense_evasion"]
    },
    {
        "rule": "Password File Modification",
        "description": "Direct modification of /etc/passwd or /etc/group, a highly suspicious sign of privilege escalation.",
        "severity": "critical", "type": "Privilege Escalation (T1098)", "logsource": "file_event",
        "detection": { "keywords": ["/etc/passwd", "/etc/group"], "field": "path" },
        "tags": ["attack.privilege_escalation"]
    },
    {
        "rule": "Potential Web Shell Dropped",
        "description": "A file with a common web shell extension was created in a web server root directory.",
        "severity": "high", "type": "Persistence (T1505.003)", "logsource": "file_event",
        "detection": { "keywords": ["/var/www/html", ".php", ".jsp", ".aspx"], "field": "path" },
        "tags": ["attack.persistence", "attack.initial_access"]
    },
    {
        "rule": "New Systemd Service Created",
        "description": "A new service file was created in a systemd directory, a common method for achieving root-level persistence.",
        "severity": "high", "type": "Persistence (T1543.002)", "logsource": "file_event",
        "detection": { "keywords": ["/etc/systemd/system/", ".service"], "field": "path" },
        "tags": ["attack.persistence", "attack.privilege_escalation"]
    },
    {
        "rule": "Suspicious File Extension Downloaded",
        "description": "A file with a potentially executable or script-based extension was downloaded.",
        "severity": "medium", "type": "Execution (T1204.002)", "logsource": "file_event",
        "detection": { "keywords": [".sh", ".py", ".elf", ".bin"], "field": "path" },
        "tags": ["attack.execution"]
    },
    {
        "rule": "Potential Ransomware Note",
        "description": "Creation of a file with a name commonly used for ransomware notes (heuristic).",
        "severity": "critical", "type": "Impact (T1490)", "logsource": "file_event",
        "detection": { "keywords": ["readme.txt", "decrypt_files", "how_to_recover"], "field": "path" },
        "tags": ["attack.impact"]
    },
    {
        "rule": "Connection to Crypto-Mining Pool",
        "description": "An outbound network connection was made to a known cryptocurrency mining pool domain (heuristic).",
        "severity": "medium", "type": "Impact (T1496)", "logsource": "network_conn",
        "detection": { "keywords": ["pool.supportxmr.com", "monerohash.com", "xmrpool.eu"], "field": "remote_address" },
        "tags": ["attack.impact"]
    },
    {
        "rule": "Connection to Dynamic DNS Provider",
        "description": "A network connection was made to a dynamic DNS domain, which is often used for C2 infrastructure.",
        "severity": "low", "type": "Command and Control (T1568.002)", "logsource": "network_conn",
        "detection": { "keywords": [".ddns.net", ".no-ip.com", ".duckdns.org"], "field": "remote_address" },
        "tags": ["attack.command_and_control"]
    },
    {
        "rule": "Connection to IP Address on Web Port",
        "description": "An outbound connection was made to a raw IP address on a common web port (80/443), bypassing DNS.",
        "severity": "medium", "type": "Command and Control (T1071.001)", "logsource": "network_conn",
        "detection": { "keywords": [":80", ":443"], "field": "remote_address" },
        "tags": ["attack.command_and_control"]
    },
    {
        "rule": "Interactive Shell Network Connection",
        "description": "An interactive shell process (like bash or sh) made a direct outbound network connection, indicating a possible reverse shell.",
        "severity": "high", "type": "Command and Control (T1071)", "logsource": "network_conn",
        "detection": { "keywords": [], "field": "" },
        "tags": ["attack.command_and_control"]
    },
    {
        "rule": "Connection to Known Tor Node",
        "description": "An outbound connection was made to an IP address associated with a Tor entry node (heuristic).",
        "severity": "medium", "type": "Command and Control (T1090.003)",
        "logsource": "network_conn",
        "detection": { "keywords": ["tor-exit", "torserver.net"], "field": "remote_address" },
        "tags": ["attack.command_and_control"]
    }
]
