# 🛡️ Decoy-Based IDS/IPS Using Honeypot Logs

A Machine Learning-powered Intrusion Detection and Prevention System (IDS/IPS) that integrates **Cowrie**, **Dionaea**, and **Suricata** honeypot/IDS logs to detect and automatically block malicious IPs using **Isolation Forest + Random Forest** models.

---

## 📁 Project Structure

```
honeypot-ids-project/
├── cowrie/                   # Cowrie SSH/Telnet Honeypot
│   └── unified_parser.py     # Parses honeypot logs → ids_ml_features.csv
├── ids_project/
│   ├── main.py               # Live IDS/IPS detection engine
│   ├── train_models.py       # ML model training script
│   ├── dashboard.py          # Web dashboard (Flask)
│   ├── detect.py             # Detection logic
│   ├── blocker.py            # IP blocking module
│   ├── models/               # Auto-generated trained models (*.pkl)
│   ├── datasets/             # CIC-IDS2017 datasets (place here)
│   ├── figures/              # Auto-generated IEEE evaluation graphs
│   └── logs/                 # Auto-generated detection logs
├── .gitignore
└── README.md
```

---

## ⚙️ Requirements

- **OS:** Kali Linux (VirtualBox VM)
- **Python:** 3.8+
- **Docker:** For Dionaea
- **Tools:** Cowrie, Suricata, iptables

---

## 🚀 Setup & Installation

### STEP 1 — Clone the Repository

```bash
git clone https://github.com/jeyabalan07/Decoy-Based-IDS-IPS-Using-Honeypot-Logs.git
cd Decoy-Based-IDS-IPS-Using-Honeypot-Logs
```

---

### STEP 2 — Set Up Python Virtual Environment

> ⚠️ **This venv must be activated before running any project Python scripts.**

```bash
cd ~
python3 -m venv cowrie-env
source cowrie-env/bin/activate
```

Install Cowrie's required packages from `requirements.txt`:

```bash
pip install -r ~/cowrie/requirements.txt
```

Install additional packages needed for the IDS project:

```bash
pip install flask joblib scikit-learn numpy pandas matplotlib seaborn
```

---

### STEP 3 — Install & Configure Cowrie (SSH/Telnet Honeypot)

```bash
cd ~/cowrie
cp etc/cowrie.cfg.dist etc/cowrie.cfg
nano etc/cowrie.cfg
```

Change the SSH port (default 2222):
```
[ssh]
listen_port = 2222
```

Start Cowrie **(venv must be active)**:

```bash
source ~/cowrie-env/bin/activate
bin/cowrie start
```

Verify it's running:

```bash
bin/cowrie status
```

Cowrie logs will be saved at:
```
~/cowrie/var/log/cowrie/cowrie.json
```

---

### STEP 4 — Install & Run Dionaea (Malware Honeypot via Docker)

Install Docker if not already installed:

```bash
sudo apt update
sudo apt install -y docker.io
sudo systemctl start docker
sudo systemctl enable docker
```

Pull and run Dionaea container:

```bash
sudo docker run -d \
  --name dionaea \
  -p 21:21 -p 23:23 -p 80:80 -p 443:443 \
  -p 445:445 -p 1433:1433 -p 3306:3306 \
  dinotools/dionaea
```

Verify it's running:

```bash
sudo docker ps
```

Dionaea logs will be at:
```
/opt/dionaea/logs/dionaea.log
```

---

### STEP 5 — Install & Configure Suricata (Network IDS)

```bash
sudo apt update
sudo apt install -y suricata
sudo suricata-update
```

Check your network interface name:

```bash
ip a
```

Start Suricata (replace `eth0` with your actual interface):

```bash
sudo suricata -D -i eth0 --pidfile /var/run/suricata.pid
```

Suricata logs will be at:
```
/var/log/suricata/eve.json
```

---

### STEP 6 — Set Up the IDS Project Folder

```bash
cd ~
mkdir -p ids_project/models ids_project/logs ids_project/datasets
cp -r ~/honeypot-ids-project/ids_project/* ~/ids_project/
```

---

### STEP 7 — Add CIC-IDS2017 Datasets (Optional but Recommended)

Download CIC-IDS2017 CSV files from:
> https://www.unb.ca/cic/datasets/ids-2017.html

Place them inside:
```
~/ids_project/datasets/# 🛡️ Decoy-Based IDS/IPS Using Honeypot Logs

A Machine Learning-powered Intrusion Detection and Prevention System (IDS/IPS) that integrates **Cowrie**, **Dionaea**, and **Suricata** honeypot/IDS logs to detect and automatically block malicious IPs using **Isolation Forest + Random Forest** models.

---

## 📁 Project Structure

```
honeypot-ids-project/
├── cowrie/                   # Cowrie SSH/Telnet Honeypot
│   └── unified_parser.py     # Parses honeypot logs → ids_ml_features.csv
├── ids_project/
│   ├── main.py               # Live IDS/IPS detection engine
│   ├── train_models.py       # ML model training script
│   ├── dashboard.py          # Web dashboard (Flask)
│   ├── detect.py             # Detection logic
│   ├── blocker.py            # IP blocking module
│   ├── models/               # Auto-generated trained models (*.pkl)
│   ├── datasets/             # CIC-IDS2017 datasets (place here)
│   ├── figures/              # Auto-generated IEEE evaluation graphs
│   └── logs/                 # Auto-generated detection logs
├── .gitignore
└── README.md
```

---

## ⚙️ Requirements

- **OS:** Kali Linux (VirtualBox VM)
- **Python:** 3.8+
- **Docker:** For Dionaea
- **Tools:** Cowrie, Suricata, iptables

---

## 🚀 Setup & Installation

### STEP 1 — Clone the Repository

```bash
git clone https://github.com/jeyabalan07/Decoy-Based-IDS-IPS-Using-Honeypot-Logs.git
cd Decoy-Based-IDS-IPS-Using-Honeypot-Logs
```

---

### STEP 2 — Set Up Python Virtual Environment

> ⚠️ **This venv must be activated before running any project Python scripts.**

```bash
cd ~
python3 -m venv cowrie-env
source cowrie-env/bin/activate
```

Install Cowrie's required packages from `requirements.txt`:

```bash
pip install -r ~/cowrie/requirements.txt
```

Install additional packages needed for the IDS project:

```bash
pip install flask joblib scikit-learn numpy pandas matplotlib seaborn
```

---

### STEP 3 — Install & Configure Cowrie (SSH/Telnet Honeypot)

```bash
cd ~/cowrie
cp etc/cowrie.cfg.dist etc/cowrie.cfg
nano etc/cowrie.cfg
```

Change the SSH port (default 2222):
```
[ssh]
listen_port = 2222
```

Start Cowrie **(venv must be active)**:

```bash
source ~/cowrie-env/bin/activate
bin/cowrie start
```

Verify it's running:

```bash
bin/cowrie status
```

Cowrie logs will be saved at:
```
~/cowrie/var/log/cowrie/cowrie.json
```

---

### STEP 4 — Install & Run Dionaea (Malware Honeypot via Docker)

Install Docker if not already installed:

```bash
sudo apt update
sudo apt install -y docker.io
sudo systemctl start docker
sudo systemctl enable docker
```

Pull and run Dionaea container:

```bash
sudo docker run -d \
  --name dionaea \
  -p 21:21 -p 23:23 -p 80:80 -p 443:443 \
  -p 445:445 -p 1433:1433 -p 3306:3306 \
  dinotools/dionaea
```

Verify it's running:

```bash
sudo docker ps
```

Dionaea logs will be at:
```
/opt/dionaea/logs/dionaea.log
```

---

### STEP 5 — Install & Configure Suricata (Network IDS)

```bash
sudo apt update
sudo apt install -y suricata
sudo suricata-update
```

Check your network interface name:

```bash
ip a
```

Start Suricata (replace `eth0` with your actual interface):

```bash
sudo suricata -D -i eth0 --pidfile /var/run/suricata.pid
```

Suricata logs will be at:
```
/var/log/suricata/eve.json
```

---

### STEP 6 — Set Up the IDS Project Folder

```bash
cd ~
mkdir -p ids_project/models ids_project/logs ids_project/datasets
cp -r ~/honeypot-ids-project/ids_project/* ~/ids_project/
```

---

### STEP 7 — Add CIC-IDS2017 Datasets (Optional but Recommended)

Download CIC-IDS2017 CSV files from:
> https://www.unb.ca/cic/datasets/ids-2017.html

Place them inside:
```
~/ids_project/datasets/
```

Example files:
```
Monday-WorkingHours.pcap_ISCX.csv
Tuesday-WorkingHours.pcap_ISCX.csv
Wednesday-workingHours.pcap_ISCX.csv
Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv
Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv
```

> ⚠️ If no datasets are placed, the system will generate synthetic benign data automatically.

---

### STEP 8 — Generate CSV from Honeypot Logs (unified_parser.py)

> ⚠️ **Activate venv before running this.**

`unified_parser.py` reads logs from Cowrie, Dionaea, and Suricata and generates the `ids_ml_features.csv` file needed for training.

```bash
source ~/cowrie-env/bin/activate
cd ~/cowrie
python3 unified_parser.py
```

This will generate:
```
~/ids_project/ids_ml_features.csv
```

> ℹ️ Make sure Cowrie has been running long enough to have collected some attack logs before running this. The more logs collected, the better the training data.

---

### STEP 9 — Train the ML Models

> ⚠️ **Activate venv before running this.**

```bash
source ~/cowrie-env/bin/activate
cd ~/ids_project
python3 train_models.py
```

This will:
- Load `ids_ml_features.csv` (from unified_parser) + CIC-IDS2017 datasets
- Train **Isolation Forest** + **Random Forest** models
- Save models to `~/ids_project/models/`
- Generate IEEE-quality evaluation figures in `~/ids_project/figures/`

Expected output files:
```
models/isolation_forest.pkl
models/random_forest.pkl
models/scaler.pkl
models/meta.json
```

---

### STEP 10 — Run the Live IDS/IPS Detection Engine

> ⚠️ **Requires sudo for iptables access.**

```bash
sudo ~/cowrie-env/bin/python3 ~/ids_project/main.py
```

The system will:
- Monitor Cowrie, Dionaea, and Suricata logs in real time
- Use ML models to detect malicious IPs
- Automatically block detected IPs using **iptables**
- Auto-unblock IPs after **24 hours**

---

### STEP 11 — Launch the Web Dashboard

> ⚠️ **Activate venv before running this.**

Open a **new terminal**:

```bash
source ~/cowrie-env/bin/activate
python3 ~/ids_project/dashboard.py
```

Then open your browser and go to:
```
http://<your-vm-ip>:5000
```

Find your VM IP using:
```bash
ip a
```

Dashboard features:
- 🟢 Start/Stop Cowrie, Dionaea, Suricata
- 🔴 Start/Stop ML Detection Engine
- 📋 Live detection logs
- 🚫 View & unblock blocked IPs
- 📊 Threat meter & stats

---

## 🔄 Quick Start (After First Setup)

Once everything is installed, use this order every time:

```bash
# 1. Activate venv
source ~/cowrie-env/bin/activate

# 2. Start Cowrie
cd ~/cowrie && bin/cowrie start

# 3. Start Dionaea
sudo docker start dionaea

# 4. Start Suricata (replace eth0 with your interface)
sudo suricata -D -i eth0 --pidfile /var/run/suricata.pid

# 5. (Optional) Re-parse logs to update training data
python3 ~/cowrie/unified_parser.py

# 6. (Optional) Retrain models if new data is available
python3 ~/ids_project/train_models.py

# 7. Start Dashboard (new terminal)
source ~/cowrie-env/bin/activate
python3 ~/ids_project/dashboard.py

# 8. Start Detection Engine
sudo ~/cowrie-env/bin/python3 ~/ids_project/main.py
```

---

## 🛑 Stopping Everything

```bash
# Stop Cowrie
cd ~/cowrie && bin/cowrie stop

# Stop Dionaea
sudo docker stop dionaea

# Stop Suricata
sudo kill $(cat /var/run/suricata.pid)

# Stop Detection / Dashboard
# Press Ctrl+C in their respective terminals
```

---

## 📊 ML Models Used

| Model | Purpose | Threshold |
|---|---|---|
| Isolation Forest | Anomaly detection | score < -0.3 |
| Random Forest | Classification | confidence >= 0.80 |

---

## 🔍 Log File Locations

| Component | Log Path |
|---|---|
| Cowrie | `~/cowrie/var/log/cowrie/cowrie.json` |
| Dionaea | `/opt/dionaea/logs/dionaea.log` |
| Suricata | `/var/log/suricata/eve.json` |
| Parsed Features | `~/ids_project/ids_ml_features.csv` |
| Detections | `~/ids_project/logs/detections.log` |
| Blocked IPs | `~/ids_project/logs/blocked_ips.json` |

---

## ⚠️ Important Notes

- Always activate venv (`source ~/cowrie-env/bin/activate`) before running any Python script
- Run `main.py` with `sudo` — it needs iptables access to block IPs
- Run `unified_parser.py` after collecting honeypot logs to generate fresh training data
- Edit the `WHITELIST` set in `main.py` to add your own machine IPs so they are never blocked
- The dashboard runs on port **5000** — make sure it's not blocked by your firewall

---

## 👤 Author

**Jeyabalan** — Kali Linux, VirtualBox  
Project: Decoy-Based IDS/IPS Using Honeypot Logs
```

Example files:
```
Monday-WorkingHours.pcap_ISCX.csv
Tuesday-WorkingHours.pcap_ISCX.csv
Wednesday-workingHours.pcap_ISCX.csv
Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv
Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv
```

> ⚠️ If no datasets are placed, the system will generate synthetic benign data automatically.

---

### STEP 8 — Generate CSV from Honeypot Logs (unified_parser.py)

> ⚠️ **Activate venv before running this.**

`unified_parser.py` reads logs from Cowrie, Dionaea, and Suricata and generates the `ids_ml_features.csv` file needed for training.

```bash
source ~/cowrie-env/bin/activate
cd ~/cowrie
python3 unified_parser.py
```

This will generate:
```
~/ids_project/ids_ml_features.csv
```

> ℹ️ Make sure Cowrie has been running long enough to have collected some attack logs before running this. The more logs collected, the better the training data.

---

### STEP 9 — Train the ML Models

> ⚠️ **Activate venv before running this.**

```bash
source ~/cowrie-env/bin/activate
cd ~/ids_project
python3 train_models.py
```

This will:
- Load `ids_ml_features.csv` (from unified_parser) + CIC-IDS2017 datasets
- Train **Isolation Forest** + **Random Forest** models
- Save models to `~/ids_project/models/`
- Generate IEEE-quality evaluation figures in `~/ids_project/figures/`

Expected output files:
```
models/isolation_forest.pkl
models/random_forest.pkl
models/scaler.pkl
models/meta.json
```

---

### STEP 10 — Run the Live IDS/IPS Detection Engine

> ⚠️ **Requires sudo for iptables access.**

```bash
sudo ~/cowrie-env/bin/python3 ~/ids_project/main.py
```

The system will:
- Monitor Cowrie, Dionaea, and Suricata logs in real time
- Use ML models to detect malicious IPs
- Automatically block detected IPs using **iptables**
- Auto-unblock IPs after **24 hours**

---

### STEP 11 — Launch the Web Dashboard

> ⚠️ **Activate venv before running this.**

Open a **new terminal**:

```bash
source ~/cowrie-env/bin/activate
python3 ~/ids_project/dashboard.py
```

Then open your browser and go to:
```
http://<your-vm-ip>:5000
```

Find your VM IP using:
```bash
ip a
```

Dashboard features:
- 🟢 Start/Stop Cowrie, Dionaea, Suricata
- 🔴 Start/Stop ML Detection Engine
- 📋 Live detection logs
- 🚫 View & unblock blocked IPs
- 📊 Threat meter & stats

---

## 🔄 Quick Start (After First Setup)

Once everything is installed, use this order every time:

```bash
# 1. Activate venv
source ~/cowrie-env/bin/activate

# 2. Start Cowrie
cd ~/cowrie && bin/cowrie start

# 3. Start Dionaea
sudo docker start dionaea

# 4. Start Suricata (replace eth0 with your interface)
sudo suricata -D -i eth0 --pidfile /var/run/suricata.pid

# 5. (Optional) Re-parse logs to update training data
python3 ~/cowrie/unified_parser.py

# 6. (Optional) Retrain models if new data is available
python3 ~/ids_project/train_models.py

# 7. Start Dashboard (new terminal)
source ~/cowrie-env/bin/activate
python3 ~/ids_project/dashboard.py

# 8. Start Detection Engine
sudo ~/cowrie-env/bin/python3 ~/ids_project/main.py
```

---

## 🛑 Stopping Everything

```bash
# Stop Cowrie
cd ~/cowrie && bin/cowrie stop

# Stop Dionaea
sudo docker stop dionaea

# Stop Suricata
sudo kill $(cat /var/run/suricata.pid)

# Stop Detection / Dashboard
# Press Ctrl+C in their respective terminals
```

---

## 📊 ML Models Used

| Model | Purpose | Threshold |
|---|---|---|
| Isolation Forest | Anomaly detection | score < -0.3 |
| Random Forest | Classification | confidence >= 0.80 |

---

## 🔍 Log File Locations

| Component | Log Path |
|---|---|
| Cowrie | `~/cowrie/var/log/cowrie/cowrie.json` |
| Dionaea | `/opt/dionaea/logs/dionaea.log` |
| Suricata | `/var/log/suricata/eve.json` |
| Parsed Features | `~/ids_project/ids_ml_features.csv` |
| Detections | `~/ids_project/logs/detections.log` |
| Blocked IPs | `~/ids_project/logs/blocked_ips.json` |

---

## ⚠️ Important Notes

- Always activate venv (`source ~/cowrie-env/bin/activate`) before running any Python script
- Run `main.py` with `sudo` — it needs iptables access to block IPs
- Run `unified_parser.py` after collecting honeypot logs to generate fresh training data
- Edit the `WHITELIST` set in `main.py` to add your own machine IPs so they are never blocked
- The dashboard runs on port **5000** — make sure it's not blocked by your firewall

---

## 👤 Authors

**Jeyabalan/Yasir** — Kali Linux, VirtualBox  
Project: Decoy-Based IDS/IPS Using Honeypot Logs
