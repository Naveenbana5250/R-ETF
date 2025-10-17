# 🛡️ R-ETF Agent: Real-Time Cross-Platform Endpoint Telemetry Framework

R-ETF (Real-Time Endpoint Telemetry Framework) is an open-source, multi-language endpoint security agent designed for **real-time telemetry collection, behavioral detection, and SOC-grade visualization**.  
Developed as MVP, it demonstrates how an enterprise-class EDR can be built entirely using **zero-cost, open-source technologies**.

---

## System Architecture

The agent is built using a **modular four-language architecture**, combining low-level performance, interoperability, and analytics capability.  
Each component runs as an independent microservice communicating through JSON over **standard I/O pipes**.

Rust Collector → [Pipe] → Java Manager → [Pipe] → Python Engine → [HTTP] → Node.js Dashboard


| Component               | Language             | Purpose                                                                                 |
|--------------------------|---------------------|-----------------------------------------------------------------------------------------|
| **Rust Collector**       | Rust                | Collects process, file, and network telemetry with minimal overhead.                    |
| **Java Manager**         | Java                | Supervises Rust/Python processes, manages configs, and coordinates I/O.                 |
| **Python Orchestrator**  | Python              | Applies 30+ Sigma-style behavioral rules to detect suspicious activity.                 |
| **Node.js Dashboard**    | Node.js + Socket.IO | Real-time web dashboard for SOC visualization and alert streaming.                      |


---

## Key Features

- **Real-Time Telemetry:** Continuous monitoring of process, network, and file activity.  
- **MITRE ATT&CK Mapping:** Every detection rule aligns to ATT&CK TTPs for analyst clarity.  
- **Low CPU Overhead:** Verified < 5 % total CPU utilization (see performance benchmark).  
- **AI-Assisted Insight Panel:** Contextual alert explanations and remediation guidance.  
- **Full CI/CD Automation:** GitHub Actions workflow builds, tests, and validates alerts end-to-end.  

---

## Installation & Setup Guide (Ubuntu 22.04 / Debian)

### **Step 1 – Install Prerequisites**

```bash
sudo apt update
sudo apt install -y default-jdk python3-pip nodejs npm libudev-dev netcat-openbsd
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"
pip3 install requests
```

### Step 2 – Clone the Repository
git clone https://github.com/Naveenbana5250/R-ETF.git
cd R-ETF

### Step 3 – Build the Components

Rust Collector
```bash
cd rust_collector
cargo build --release
cd ..
```

Java Manager
```bash
cd java_manager
javac AgentManager.java
cd ..
```
### Step 4 – Run the Agent
Terminal 1 – Start the Node.js Dashboard
```bash
cd node_ui
npm install
node server.js
  ```

UI runs at http://localhost:4000
 or public IP : 4000.
Keep this terminal active.

Terminal 2 – Start the Java Manager
```bash
cd /path/to/R-ETF
sudo java -cp java_manager AgentManager
```

The manager initializes all modules — Rust Collector + Python Rule Engine — and begins live telemetry capture.

### Step 5 – Validate via Test Harness

Run automated behavioral tests that simulate malicious actions:
```bash
cd /path/to/R-ETF
chmod +x test_harness.sh
sudo ./test_harness.sh
```

You’ll see alerts populate on the web dashboard in real time, confirming complete agent functionality.

---
## Performance Validation
### CPU Profiling (htop Result)

R-ETF operates with ~2 % CPU usage, maintaining the < 5 % benchmark requirement.
```ngnix
htop
```

---
## Agent SDK — Adding Custom Detection Rules

The detection logic resides in python_orchestrator/rules.py.

Detect Sudoers File Access
```Python
{
    "rule": "Sudoers File Access Attempt",
    "description": "Read access to /etc/sudoers indicating privilege escalation reconnaissance.",
    "severity": "high",
    "type": "Privilege Escalation (T1548)",
    "logsource": "file_event",
    "detection": { "keywords": ["/etc/sudoers"], "field": "path" },
    "tags": ["attack.privilege_escalation", "attack.discovery"]
}
```

Reload by restarting the agent:
```bash
sudo java -cp java_manager AgentManager
```

Trigger:
```bash
sudo cat /etc/sudoers
```

An alert titled “Sudoers File Access Attempt” appears instantly in the dashboard.

---
## CI/CD Pipeline Automation

GitHub Actions workflow: .github/workflows/ci.yml

### Pipeline Jobs

1. build-and-package – Compiles Rust + Java modules, installs Python/Node deps, and uploads release artifact.

2. integration-test – Deploys agent in a clean VM, runs test_harness.sh, and verifies expected alerts.
```bash
git add .
git commit -m "feat: Add initial CI pipeline configuration"
git push origin main
```

---
## Threat Intelligence Dashboard

The Node.js UI renders live detections with contextual insights, mapped to MITRE ATT&CK TTPs.


### Test Harness Execution
./test_harness.sh


Live Alert Stream
!!! ALERT Triggered: Connection to IP Address on Web Port (medium)
!!! ALERT Triggered: Potential Ransomware Note (critical)
!!! ALERT Triggered: Suspicious Process Execution: Netcat (high)

---
## Validation Screens
### Performance Validation (htop)

CPU usage consistently below 5 % confirming KPI compliance.

### CI/CD Workflow

All jobs — build-and-package and integration-test — pass successfully on GitHub Actions.

### Dashboard Output

Alerts visualized in real time, enriched with AI-assisted recommendations and MITRE ATT&CK mapping.

---
## Technical KPIs and Outcomes
| KPI                    | Target                               | Achieved                   |
| ---------------------- | ------------------------------------ | -------------------------- |
| Cross-Platform Support | Linux (MVP), Extensible to Win/macOS |  Done                      |
| CPU Overhead           | < 5 % avg                            |  3.6% measured             |
| Detection Rules        | ≥ 30                                 |  32 rules implemented      |
| CI/CD Automation       | Full build + test validation         |  Passed (see Actions log)  |
| SOC Visualization      | Live Dashboard + AI Assistant        |  Operational               |

---
## Tech Stack
| Layer                | Technology                       |
| -------------------- | -------------------------------- |
| **Telemetry**        | Rust + libudev + procfs          |
| **Process Manager**  | Java 11                          |
| **Detection Engine** | Python 3.9 (Sigma-style Rules)   |
| **Visualization**    | Node.js 20 + Express + Socket.IO |
| **Automation**       | GitHub Actions CI/CD             |
| **Environment**      | Ubuntu 22.04 LTS                 |

---
##  Summary

R-ETF Agent validates the complete life-cycle of a modern, open-source EDR:
Collection → Detection → Visualization → Automation → Validation.
Built entirely using free, cross-platform toolchains, it demonstrates how endpoint telemetry, behavioral analytics, and CI/CD automation can converge into a unified, high-efficiency security framework.
