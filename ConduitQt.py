import sys
import os
import re
import time
import platform
import statistics
import ipaddress
from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QHBoxLayout, QPushButton, QLabel, QLineEdit, QInputDialog,
                             QCheckBox, QListWidget, QListWidgetItem, QPlainTextEdit, 
                             QFileDialog, QMessageBox, QFrame, QAbstractItemView, 
                             QRadioButton, QButtonGroup, QDialog, QFormLayout)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QFont
from fabric import Connection, Config

# --- PLATFORM SPECIFIC FIXES ---
if platform.system() == "Darwin":  # Darwin is the internal name for macOS
    # Fix for tiny fonts on Retina displays
    QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)
    print("[INFO] macOS High-DPI Scaling Enabled")

CONDUIT_URL = "https://github.com/ssmirr/conduit/releases/download/2fd31d4/conduit-linux-amd64"

# --- 1. Dialog for Add/Edit (Compact Design) ---
class ServerDialog(QDialog):
    def __init__(self, parent=None, data=None):
        super().__init__(parent)
        self.setWindowTitle("Edit Server" if data else "Add New Server")
        self.layout = QFormLayout(self)
        self.layout.setContentsMargins(15, 15, 15, 15)
        self.layout.setSpacing(10)

        self.name_edit = QLineEdit(data['name'] if data else "")
        self.ip_edit = QLineEdit(data['ip'] if data else "")
        self.port_edit = QLineEdit(data['port'] if data else "22")
        self.user_edit = QLineEdit(data['user'] if data else "root")
        self.pass_edit = QLineEdit(data['pass'] if data else "")
        self.pass_edit.setEchoMode(QLineEdit.Password)
        
        self.layout.addRow("Name:", self.name_edit)
        self.layout.addRow("IP/Hostname:", self.ip_edit)
        self.layout.addRow("Port:", self.port_edit)
        self.layout.addRow("Username:", self.user_edit)
        self.layout.addRow("Password:", self.pass_edit)
        
        btns = QHBoxLayout()
        self.btn_apply = QPushButton("Apply")
        self.btn_cancel = QPushButton("Cancel")
        btns.addWidget(self.btn_apply); btns.addWidget(self.btn_cancel)
        self.layout.addRow(btns)
        
        self.btn_apply.clicked.connect(self.accept)
        self.btn_cancel.clicked.connect(self.reject)

    def get_data(self):
        return {
            "name": self.name_edit.text().strip(),
            "ip": self.ip_edit.text().strip(),
            "port": self.port_edit.text().strip(),
            "user": self.user_edit.text().strip(),
            "pass": self.pass_edit.text().strip()
        }

# --- 2. Background Worker (SSH) ---
class ServerWorker(QThread):
    log_signal = pyqtSignal(str)

    def __init__(self, action, targets, config):
        super().__init__()
        self.action = action
        self.targets = targets
        self.config = config

    def run(self):
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(self.ssh_task, s) for s in self.targets]
            for f in as_completed(futures):
                self.log_signal.emit(f.result())

    def ssh_task(self, s):
        try:
            p = int(s['port'])
            user = s['user'].strip()
            password = s['pass'].strip()
            
            # Cross-platform home directory
            home = os.path.expanduser("~")
            
            potential_keys = [
                os.path.join(home, ".ssh", "id_conduit")
            ]
            # Filter to only keys that actually exist on your Windows machine
            valid_keys = [k for k in potential_keys if os.path.exists(k)]

            if not password:
                # Key-based: Explicitly tell Fabric which files to use
                connect_params = {
                    "timeout": 15,
                    "key_filename": valid_keys,
                    "look_for_keys": True,
                    "allow_agent": True
                }
                cfg = Config()
                use_sudo = (user != "root") # If not root, we might still need sudo even with keys
            else:
                # Password-based
                connect_params = {"password": password, "timeout": 10}
                cfg = Config(overrides={'sudo': {'password': password}})
                use_sudo = True

            with Connection(host=s['ip'], user=user, port=p, 
                            connect_kwargs=connect_params, config=cfg) as c:
                
                def run_cmd(cmd):
                    # If we have a password, use sudo; otherwise run direct
                    if use_sudo and password:
                        return c.sudo(cmd, hide=True, warn=True)
                    else:
                        return c.run(cmd, hide=True, warn=True)

                if self.action == "reset":
                    # 1. Stop the service
                    run_cmd("systemctl stop conduit")
                    time.sleep(2)
                    # 2. Wipe the data directory (CAUTION: Destructive)
                    # We use -rf to ensure it clears everything inside
                    run_cmd("rm -rf /var/lib/conduit/*")
                    
                    # 3. Apply Config if requested
                    if self.config['update']:
                        cmd = f"/opt/conduit/conduit start --max-clients {self.config['clients']} --bandwidth {self.config['bw']} --data-dir /var/lib/conduit"
                        run_cmd(f"sed -i 's|^ExecStart=.*|ExecStart={cmd}|' /etc/systemd/system/conduit.service")
                        run_cmd("systemctl daemon-reload")
                    
                    # 4. Start service
                    run_cmd("systemctl start conduit")
                    return f"[!] {s['name']}: FULL RESET COMPLETE (Data wiped & restarted)."

                if self.action == "status":
                    # 1. Get the standard systemctl status (Active/Inactive)
                    status_res = run_cmd("systemctl is-active conduit")
                    current_status = status_res.stdout.strip() if status_res.ok else "inactive"
                    current_status = f"[*] {s['name']} ({s['ip']}): { current_status.upper()}"

                    # 2. Get the last 5 lines of the journal
                    log_res = run_cmd("journalctl -u conduit.service -n 10 --no-pager")
                    journal_logs = log_res.stdout if log_res.ok else "No logs found."

                    # 3. Combine them for the UI
                    output = f"--- STATUS: {current_status} ---\n{journal_logs}"
                    return output

                service_file = "/etc/systemd/system/conduit.service"
                
                if self.action == "stop":
                    c.sudo("systemctl stop conduit", hide=True)
                    return f"[-] {s['name']} Stopped."

                if self.action in ["start", "restart"]:
                    if self.config['update']:
                        exec_cmd = f"/opt/conduit/conduit start --max-clients {self.config['clients']} --bandwidth {self.config['bw']} --data-dir /var/lib/conduit"
                        sed_cmd = f"sed -i 's|^ExecStart=.*|ExecStart={exec_cmd}|' {service_file}"
                        c.sudo(sed_cmd, hide=True)
                        c.sudo("systemctl daemon-reload", hide=True)
                    
                    c.sudo(f"systemctl {self.action} conduit", hide=True)
                    return f"[+] {s['name']} {self.action.capitalize()}ed."
                
        except Exception as e:
            return f"[!] {s['name']} Error: {str(e)}"            

class StatsWorker(QThread):
    finished_signal = pyqtSignal(str)

    def __init__(self, targets, display_mode):
        super().__init__()
        self.targets = targets
        self.display_mode = display_mode

    def run(self):
        results = []
        with ThreadPoolExecutor(max_workers=15) as executor:
            futures = [executor.submit(self.get_stats, s) for s in self.targets]
            for f in as_completed(futures):
                results.append(f.result())
        
        results = sorted(results, key=lambda x: x.get('mbps_val', 0), reverse=True)
        self.finished_signal.emit(self.generate_table(results))


    def get_stats(self, s):
        display_label = s['name'] if self.display_mode == 'name' else s['ip']
        res = {"label": display_label, "success": False, "clients": "0", "up": "0B", 
               "down": "0B", "uptime": "Offline", "mbps": "0.00", "mbps_val": 0.0,
               "up_1h": "0B", "down_1h": "0B"}
        
        try:
            home = os.path.expanduser("~")
            key_path = os.path.join(home, ".ssh", "id_conduit")
            connect_kwargs = {"key_filename": [key_path], "look_for_keys": False, "allow_agent": False, "timeout": 10}

            with Connection(host=s['ip'], user=s['user'], port=int(s['port']), connect_kwargs=connect_kwargs) as conn:
                # Command to get last 1 hour of raw stats
#                cmd = "journalctl -u conduit.service --since '1 hour ago' -o cat | grep '\\[STATS\\]'"
                cmd = "journalctl -u conduit.service --since '1 hour ago' -o cat | grep -F '[STATS]'"
                result = conn.run(cmd, hide=True, timeout=15)
                output = result.stdout.strip()

                if output:
                    lines = output.splitlines()
                    # Pattern for: [STATS] Clients: 72 | Up: 236.8 MB | Down: 1.6 GB | Uptime: 37m54s
                    pattern = re.compile(r"\[STATS\].*?(?:Clients|Connected):\s*(\d+)\s*\|\s*Up:\s*([\d\.]+)\s*([TGMK]?B)\s*\|\s*Down:\s*([\d\.]+)\s*([TGMK]?B)\s*\|\s*Uptime:\s*([\w\d]+)")
#                    pattern = re.compile(r"Clients:\s*(\d+)\s*\|\s*Up:\s*([\d\.]+)\s*([TGMK]?B)\s*\|\s*Down:\s*([\d\.]+)\s*([TGMK]?B)\s*\|\s*Uptime:\s*([\w\d]+)")
                    
                    data_points = []
                    for line in lines:
                        m = pattern.search(line)
                        if m:
                            data_points.append({
                                'c': int(m.group(1)),
                                'u': self.parse_to_bytes(f"{m.group(2)} {m.group(3)}"),
                                'd': self.parse_to_bytes(f"{m.group(4)} {m.group(5)}"),
                                'ut': m.group(6)
                            })

                    if data_points:
                        res["success"] = True
                        first = data_points[0]
                        last = data_points[-1]

                        # Calculate Averages
                        avg_clients = sum(d['c'] for d in data_points) / len(data_points)
                        res["clients"] = str(int(round(avg_clients)))

                        # Cumulative Totals (Last Record)
                        res["up"] = self.format_bytes(last['u'])
                        res["down"] = self.format_bytes(last['d'])
                        res["uptime"] = last['ut']

                        # Hourly Growth (Delta)
                        res["up_1h"] = self.format_bytes(max(0, last['u'] - first['u']))
                        res["down_1h"] = self.format_bytes(max(0, last['d'] - first['d']))

                        # Mbps logic
                        total_sec = self.uptime_to_seconds(res["uptime"])
                        if total_sec > 0:
                            mbps = (last['d'] * 8) / total_sec / 10**6
                            res["mbps_val"] = mbps
                            res["mbps"] = f"{mbps:.2f}"
                else:
                    res["uptime"] = "No Data (1h)"

        except Exception as e:
            res["uptime"] = "Conn Error"
            
        return res

    def format_bytes(self, size):
        """Helper to convert bytes back to human readable string"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024.0:
                return f"{size:.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} PB"


    def uptime_to_seconds(self, uptime_str):
        try:
            # Handle formats like 6h55m19s
            h = int(re.search(r'(\d+)h', uptime_str).group(1)) if 'h' in uptime_str else 0
            m = int(re.search(r'(\d+)m', uptime_str).group(1)) if 'm' in uptime_str else 0
            s = int(re.search(r'(\d+)s', uptime_str).group(1)) if 's' in uptime_str else 0
            return (h * 3600) + (m * 60) + s
        except:
            return 0

    def parse_to_bytes(self, s):
        if not s or "0B" in s: return 0.0
        match = re.search(r'([\d\.]+)', s)
        if not match: return 0.0
        num = float(match.group(1))
        u = s.upper()
        if 'TB' in u: return num * 1024**4
        if 'GB' in u: return num * 1024**3
        if 'MB' in u: return num * 1024**2
        if 'KB' in u: return num * 1024
        return num

#    def strip_ansi(text):
#        return re.compile(r'\x1b\[[0-9;]*[a-zA-Z]').sub('', text)

    def format_bytes(self,b):
        if b == 0: return "0 B"
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if b < 1024: return f"{b:.2f} {unit}"
            b /= 1024
        return f"{b:.2f} PB"

    def generate_table(self, results):
        # 1. Main Table Generation
        # width adjusted to 105 for comfortable spacing
        width = 105
        head = f"│ {'Name/IP':<20} │ {'Clients':<8} │ {'Up (total | 1h)':<20} │ {'Down (total | 1h)':<20} │ {'Uptime':<14} │ {'Mbps':<6} │\n"
        sep = "├" + "─"*22 + "┼" + "─"*10 + "┼" + "─"*22 + "┼" + "─"*22 + "┼" + "─"*16 + "┼" + "─"*8 + "┤\n"
        
        body = ""
        valid_results = [r for r in results if r["success"]]
        
        for r in results:
            status = "✓" if r["success"] else "✗"
            if r["success"]:
                # Clients is now just the average integer string
                # Traffic format: "Total | Delta"
                up_val = f"{r['up']} | {r['up_1h']}"
                down_val = f"{r['down']} | {r['down_1h']}"
                
                body += f"│ {status} {r['label'][:18]:<18} │ {r['clients']:<8} │ {up_val:<20} │ {down_val:<20} │ {r['uptime']:<14} │ {r['mbps']:<6} │\n"
            else:
                body += f"│ {status} {r['label'][:18]:<18} │ {'-':<8} │ {'-':<20} │ {'-':<20} │ {r['uptime']:<14} │ {'0.00':<6} │\n"
        
        main_table = f"┌" + "─"*width + "┐\n" + head + sep + body + "└" + "─"*width + "┘"

        # 2. Analytics Summary Logic
        if not valid_results:
            return main_table + "\n[!] No active data to calculate analytics."

        ts = (datetime.now(timezone.utc) + timedelta(hours=3, minutes=30)).strftime('%Y-%m-%d %H:%M:%S')
        
        # Clients are already stored as average strings, so we convert back to int for analytics
        clients_list = [int(r["clients"]) for r in valid_results if r["clients"].isdigit()]
        total_clients = sum(clients_list)
        
        ups = [self.parse_to_bytes(r["up"]) for r in valid_results]
        downs = [self.parse_to_bytes(r["down"]) for r in valid_results]
        mbps_list = [r["mbps_val"] for r in valid_results]

        out = []
        out.append(f"\n--- Analytics Summary (Iran Time: {ts}) ---")
        out.append(f"Total Average Clients across all servers: {total_clients}\n")
        
        out.append(f"{'Metric':<12} │ {'Mean':<12} │ {'Median':<12} │ {'Min':<12} │ {'Max':<12}")
        sep_line = f"{'─'*13}┼{'─'*14}┼{'─'*14}┼{'─'*14}┼{'─'*14}"
        out.append(sep_line)

        def get_stat_row(label, data_list, is_bytes=False):
            if not data_list: return ""
            import statistics
            avg_val = statistics.mean(data_list)
            med_val = statistics.median(data_list)
            min_val = min(data_list)
            max_val = max(data_list)
            
            if is_bytes:
                return f"{label:<12} │ {self.format_bytes(avg_val):<12} │ {self.format_bytes(med_val):<12} │ {self.format_bytes(min_val):<12} │ {self.format_bytes(max_val):<12}"
            if label == "Clients":
                return f"{label:<12} │ {int(round(avg_val)):<12} │ {int(round(med_val)):<12} │ {int(min_val):<12} │ {int(max_val):<12}"
            return f"{label:<12} │ {avg_val:<12.2f} │ {med_val:<12.2f} │ {min_val:<12.2f} │ {max_val:<12.2f} Mbps"

        out.append(get_stat_row("Clients", clients_list))
        out.append(get_stat_row("Upload", ups, True))
        out.append(get_stat_row("Download", downs, True))
        out.append(get_stat_row("Avg Mbps", mbps_list))

        return main_table + "\n" + "\n".join(out)


class DeployWorker(QThread):
    log_signal = pyqtSignal(str)
    remove_password_signal = pyqtSignal(str)

    def __init__(self, targets, params):
        super().__init__()
        self.targets = targets
        self.params = params # password, max_clients, bandwidth, user

    def run(self):
        # Read the public key once
        home = os.path.expanduser("~")
        pub_key_path = os.path.join(home, ".ssh", "id_conduit.pub")
        
        if not os.path.exists(pub_key_path):
            self.log_signal.emit(f"[ERROR] Public key not found at: {pub_key_path}")
            return

        with open(pub_key_path, "r") as f:
            pub_key_content = f.read().strip()

        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(self.deploy_task, s, pub_key_content) for s in self.targets]
            for f in as_completed(futures):
                self.log_signal.emit(f.result())


    def deploy_task(self, s, pub_key):
        try:

            home = os.path.expanduser("~")
            key_path = os.path.join(home, ".ssh", "id_conduit")
        
            pwd = s.get('pass') 
        
            conn_params = {
                "timeout": 10,
                "banner_timeout": 20
            }

            if pwd:
                conn_params["password"] = pwd
                conn_params["look_for_keys"] = True
                conn_params["allow_agent"] = False
            else:
                # Key-only mode
                conn_params["key_filename"] = [key_path]
                conn_params["look_for_keys"] = False
                conn_params["allow_agent"] = False

            with Connection(host=s['ip'], 
                            user=self.params['user'],
                            port=int(s['port']), 
                            connect_kwargs=conn_params,
                            inline_ssh_env=True
            ) as conn:
                
                # Check if we are actually root or have access
                # This "id -u" check returns 0 for root
                res = conn.run("id -u", hide=True, warn=True)
                if not res.ok:
                    return f"[SKIP] {s['ip']}: Could not connect or not root."

                # 1. Key Injection
                conn.run("mkdir -p ~/.ssh && chmod 700 ~/.ssh", hide=True)
                conn.run(f'echo "{pub_key}" >> ~/.ssh/authorized_keys', hide=True)
                conn.run("chmod 600 ~/.ssh/authorized_keys", hide=True)

                # 2. Cleanup & Directory Prep
                conn.run("systemctl stop conduit", warn=True, hide=True)
                time.sleep(2)
                conn.run("rm -f /opt/conduit/conduit", warn=True, hide=True)
                conn.run("mkdir -p /opt/conduit", hide=True)
                # Crucial: The service hardening requires this directory to exist beforehand
                conn.run("mkdir -p /var/lib/conduit", hide=True) 

                pkg_cmd = "dnf install wget firewalld curl -y" if conn.run("command -v dnf", warn=True, hide=True).ok else "apt-get update -y && apt-get install wget firewalld curl -y"
                conn.run(pkg_cmd, hide=True)

                # 3. Download Binary
                conn.run(f"curl -L -o /opt/conduit/conduit {CONDUIT_URL}", hide=True)                
                conn.run("chmod +x /opt/conduit/conduit")

                # 4. Manually Create the Service File (Replacing 'service install')
                service_content = f"""[Unit]
Description=Psiphon Conduit inproxy service - relays traffic for users in censored regions
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/opt/conduit/conduit start --max-clients {self.params['clients']} --bandwidth {self.params['bw']} --data-dir /var/lib/conduit
Restart=always
RestartSec=10
User=root
Group=root
WorkingDirectory=/opt/conduit/

# Hardening
NoNewPrivileges=true
ProtectSystem=full
ProtectHome=read-only
ReadWritePaths=/var/lib/conduit
PrivateTmp=true

[Install]
WantedBy=multi-user.target
"""
                # Escape single quotes in the content if any (though there are none currently)
                # We use sudo tee to write to the protected system directory
                conn.run(f"echo '{service_content}' | sudo tee /etc/systemd/system/conduit.service > /dev/null")

                # 5. Reload, Enable, and Start
                conn.run("systemctl daemon-reload", hide=True)
                conn.run("systemctl enable conduit", hide=True)
                conn.run("systemctl start conduit", hide=True)
                
                if pwd:
                    self.remove_password_signal.emit(s['ip'])

                return f"[OK] {s['ip']} successfully deployed (Manual Service Config)."
        except Exception as e:
            return f"[ERROR] {s['ip']} failed: {str(e)}"

# --- 3. Main GUI Window ---
class ConduitGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Conduit Management Console")
        self.setMinimumSize(1100, 800)
        self.server_data = [] 
        self.current_path = ""
        self.init_ui()
        self.check_initial_file()

    def init_ui(self):
        central = QWidget(); self.setCentralWidget(central)
        layout = QVBoxLayout(central)

        # UI Components Setup (Labels, Edits, Frames)
        file_box = QHBoxLayout()
        self.btn_import = QPushButton("Import servers.txt")
        self.lbl_path = QLabel("No file loaded")
        file_box.addWidget(self.btn_import);
        file_box.addWidget(self.lbl_path); 
        file_box.addStretch(1)

        try:
            # Automatically extract 'version' from the URL
            version_tag = CONDUIT_URL.split('/')[-2]
        except (NameError, IndexError):
            version_tag = "Unknown"

        self.lbl_version = QLabel(f"Conduit Version: {version_tag}")
        self.lbl_version.setStyleSheet("color: gray; font-style: italic; font-size: 11px;")
        
        # This stretch pushes everything after it to the right wall
#        file_box.addStretch(1) 
        
        file_box.addWidget(self.lbl_version)
        
        layout.addLayout(file_box)

        cfg_frame = QFrame(); cfg_frame.setFrameShape(QFrame.StyledPanel)
        cfg_lay = QHBoxLayout(cfg_frame)
        cfg_lay.addWidget(QLabel("Max Clients:")); self.edit_clients = QLineEdit("225")
        cfg_lay.addWidget(self.edit_clients)
        cfg_lay.addWidget(QLabel("Max Bandwidth:")); self.edit_bw = QLineEdit("40.0")
        cfg_lay.addWidget(self.edit_bw)
        self.chk_upd = QCheckBox("Apply Config Changes"); cfg_lay.addWidget(self.chk_upd)
        self.rad_name = QRadioButton("Display Name"); self.rad_ip = QRadioButton("Display IP")
        self.rad_name.setChecked(True); cfg_lay.addWidget(self.rad_name); cfg_lay.addWidget(self.rad_ip)
        layout.addWidget(cfg_frame)

        lists_lay = QHBoxLayout()
        self.pool = QListWidget(); self.sel = QListWidget()
        for l in [self.pool, self.sel]: l.setSelectionMode(QAbstractItemView.ExtendedSelection)
        
        mid_btns = QVBoxLayout()
        self.btn_add = QPushButton("Add Server (+)")
        self.btn_edit = QPushButton("Display/Edit")
        self.btn_to_sel = QPushButton("Add Selected >>")
        self.btn_to_pool = QPushButton("<< Remove Selected")
        self.btn_del = QPushButton("Delete Server")
        self.btn_del.setStyleSheet("color: red; font-weight: bold;")
                
        mid_btns.addWidget(self.btn_to_sel); mid_btns.addWidget(self.btn_to_pool); mid_btns.addSpacing(20)
        mid_btns.addWidget(self.btn_add); mid_btns.addWidget(self.btn_edit); mid_btns.addSpacing(20)        
        mid_btns.addWidget(self.btn_del)
        
        lists_lay.addWidget(self.pool); lists_lay.addLayout(mid_btns); lists_lay.addWidget(self.sel)
        layout.addLayout(lists_lay)

        ctrl_lay = QHBoxLayout()
        self.btn_start = QPushButton("Start"); self.btn_stop = QPushButton("Stop")
        self.btn_re = QPushButton("Re-Start"); self.btn_reset = QPushButton("Reset")
        self.btn_re.setToolTip("Use Restart if server is already running.")
        self.btn_stat = QPushButton("Status"); self.btn_quit = QPushButton("Quit")
        self.btn_reset.setToolTip("Use if clients not added after hours or server waiting to connect.")
        self.btn_stats = QPushButton("Statistics")
        self.btn_stats.setStyleSheet("background-color: #2c3e50; color: white; font-weight: bold;")

        self.btn_deploy = QPushButton("Deploy")
        self.btn_deploy.setStyleSheet("background-color: #e67e22; color: white; font-weight: bold;")

        for b in [self.btn_start, self.btn_stop, self.btn_re, self.btn_reset, self.btn_stat, self.btn_stats, self.btn_deploy, self.btn_quit]:
            ctrl_lay.addWidget(b)
        layout.addLayout(ctrl_lay)


        self.console = QPlainTextEdit(); self.console.setReadOnly(True)
#        self.console.setStyleSheet("background: #1e1e1e; color: #00ff00; font-family: Consolas;")

        # 1. Set the Colors (Dark background, Green text)
        self.console.setStyleSheet("background-color: #1e1e1e; color: #00ff00;")
        
        # 2. Set the Font dynamically based on OS
        font = QFont()
        sys_name = platform.system()
        
        if sys_name == "Darwin":    # macOS
            font.setFamily("Menlo") # Standard Mac high-res mono font
            font.setPointSize(12)
        elif sys_name == "Windows": # Windows
            font.setFamily("Consolas")
            font.setPointSize(10)
        else:                       # Linux
            font.setFamily("Monospace")
            font.setPointSize(10)
            
        # This is the "Magic" line that forces perfect table alignment
        font.setStyleHint(QFont.Monospace)
        font.setFixedPitch(True)
        
        self.console.setFont(font)

        layout.addWidget(self.console)

        # Connection Slots
        self.btn_import.clicked.connect(self.import_srv)
        self.btn_add.clicked.connect(self.add_srv)
        self.btn_edit.clicked.connect(self.edit_srv)
        self.btn_to_sel.clicked.connect(self.move_to_sel)
        self.btn_to_pool.clicked.connect(self.move_to_pool)
        self.btn_del.clicked.connect(self.delete_srv)
        self.btn_quit.clicked.connect(self.close)
        self.rad_name.toggled.connect(self.sync_ui)
        self.rad_ip.toggled.connect(self.sync_ui)
#        self.btn_re.clicked.connect(lambda: QMessageBox.information(self, "Info", "Use Restart if server is already running."))

        self.btn_start.clicked.connect(lambda: self.confirm_action("start"))
        self.btn_stop.clicked.connect(lambda: self.confirm_action("stop"))
        self.btn_re.clicked.connect(lambda: self.confirm_action("restart"))
        self.btn_stat.clicked.connect(lambda: self.run_worker("status"))
        self.btn_reset.clicked.connect(self.confirm_reset)
        self.btn_stats.clicked.connect(self.run_stats)
        self.btn_deploy.clicked.connect(self.run_deploy)


    def get_validated_inputs(self):
        """Helper to validate and return clients and bandwidth."""
        raw_clients = self.edit_clients.text().strip()
        raw_bw = self.edit_bw.text().strip()

        # 1. Validate Clients (Integer 1-500)
        try:
            # Convert to float first in case user typed "200.5", then to int
            clients = int(float(raw_clients))
            if not (1 <= clients <= 500):
                raise ValueError
        except ValueError:
            QMessageBox.warning(self, "Invalid Input", 
                                "Max Clients must be a whole number between 1 and 500.")
            return None

        # 2. Validate Bandwidth (Float 1-200)
        try:
            bw = float(raw_bw)
            if not (1.0 <= bw <= 200.0):
                raise ValueError
        except ValueError:
            QMessageBox.warning(self, "Invalid Input", 
                                "Bandwidth must be a number between 1.0 and 200.0.")
            return None

        return {"clients": clients, "bw": bw}


    def run_deploy(self):
        # 1. Get targets
        selected_targets = [self.find_data_by_item(self.sel.item(i)) for i in range(self.sel.count())]
        if not selected_targets:
            QMessageBox.warning(self, "Deployment", "No servers selected.")
            return

        validated = self.get_validated_inputs()
        if not validated: return 

        valid_targets = []

        # THE WARNING GATE ---
        target_names = ", ".join([s.get('name', s['ip']) for s in selected_targets])
        
        warning_msg = (
            "⚠️ CRITICAL: FRESH DEPLOYMENT\n\n"
            f"You are about to deploy to: {target_names}\n\n"
            "This action will:\n"
            "• Connect as ROOT\n"
            "• OVERWRITE any existing conduit installation if this is a re-deployment\n"
            "• RESET all service configurations\n\n"
            "Are you absolutely sure you want to proceed?"
        )

        # Show the dialog with 'No' as the default safe choice
        reply = QMessageBox.warning(
            self, 
            "Confirm System Reinstall", 
            warning_msg,
            QMessageBox.Yes | QMessageBox.No, 
            QMessageBox.No
        )

        if reply != QMessageBox.Yes:
            self.console.appendPlainText("[CANCELLED] Deployment aborted by user.")
            return

        # --- CASE: Single Selection ---

        if len(selected_targets) == 1:
            target = selected_targets[0]
#            stored_user = target.get('user', '').strip().lower()
            target_ip = target.get('ip', '').strip()
            stored_user,stored_pwd = self.get_root_pwd_from_file(target_ip)
#            stored_pwd = target.get('pass', '').strip()
            
            # Check if we have a password AND it belongs to root
            has_root_creds = (stored_user == 'root' and stored_pwd)

            if not has_root_creds:
                # Explain why we are asking (either no pwd, or pwd is for a sub-user)
                reason = "No root password found" if not stored_pwd else f"Stored password is for user '{stored_user}', not 'root'"
                
                msg = QMessageBox(self)
                msg.setWindowTitle("Root Authentication Required")
                msg.setText(f"{reason} for {target['ip']}.\n\nHow do you want to proceed?")
                btn_pwd = msg.addButton("Enter Root Password", QMessageBox.ActionRole)
                btn_key = msg.addButton("Use Root SSH Key", QMessageBox.ActionRole)
                msg.addButton(QMessageBox.Cancel)
                
                msg.exec()
                
                if msg.clickedButton() == btn_pwd:
                    pwd_input, ok = QInputDialog.getText(self, "Root Password", "Enter Root Password:", QLineEdit.Password)
                    if ok and pwd_input:
                        target['pass'] = pwd_input
                        # We force the worker to use 'root' regardless of what's in the file
                        valid_targets = [target]
                    else: return
                elif msg.clickedButton() == btn_key:
                    target['pass'] = None 
                    valid_targets = [target]
                else:
                    return
            else:
                for s in selected_targets:
                    # If password exists, or if we want to try key-only servers
                    # For bulk, we'll assume if no password exists, we attempt Key-only
                    valid_targets.append(s)

        # 4. Final Verification
        if not valid_targets: return

        params = {
            "user": "root",
            "clients": validated['clients'], 
            "bw": validated['bw']            
        }

        # UI Feedback and Start Thread
        self.btn_deploy.setEnabled(False)
        self.btn_deploy.setText("Deploying...")
        
        self.deploy_thread = DeployWorker(valid_targets, params)
        self.deploy_thread.log_signal.connect(lambda m: self.console.appendPlainText(m))
        self.deploy_thread.remove_password_signal.connect(self.remove_password_from_file)
        self.deploy_thread.finished.connect(lambda: self.btn_deploy.setEnabled(True))
        self.deploy_thread.finished.connect(lambda: self.btn_deploy.setText("Deploy"))
        
        self.deploy_thread.start()

    def run_stats(self):
        targets = [self.find_data_by_item(self.sel.item(i)) for i in range(self.sel.count())]
        if not targets: 
            QMessageBox.warning(self, "Stats", "Add servers to the right-side list first.")
            return
            
        # Check which radio button is active
        mode = 'name' if self.rad_name.isChecked() else 'ip'
        
        self.console.appendPlainText(f"\n[>>>] Fetching Statistics (Display: {mode.upper()})...")
        self.stats_thread = StatsWorker(targets, mode)
        self.stats_thread.finished_signal.connect(lambda m: self.console.appendPlainText(m))
        self.stats_thread.start()

    def confirm_action(self, action):
        """Standard guard for Start, Stop, and Restart"""
        count = self.sel.count()
        if count == 0:
            QMessageBox.warning(self, "No Selection", "Please add servers to the 'Selected' list first.")
            return

        # Personalize the message based on the action
        action_title = action.capitalize()
        if action == "restart":
            msg = f"Are you sure you want to RESTART the Conduit service on {count} server(s)?"
            icon = QMessageBox.Question
        elif action == "stop":
            msg = f"WARNING: This will STOP the service on {count} server(s).\nContinue?"
            icon = QMessageBox.Warning
        else:
            msg = f"Start the Conduit service on {count} server(s)?"
            icon = QMessageBox.Information

        reply = QMessageBox.question(self, f"Confirm {action_title}", msg, 
                                     QMessageBox.Yes | QMessageBox.No, QMessageBox.No)

        if reply == QMessageBox.Yes:
            self.run_worker(action)

    def confirm_reset(self):
        """Safety check before performing a destructive reset"""
        targets = [self.find_data_by_item(self.sel.item(i)) for i in range(self.sel.count())]
        
        if not targets:
            QMessageBox.warning(self, "Reset", "No servers selected in the right-side list.")
            return

        msg = f"WARNING: This will stop the service and DELETE ALL DATA in /var/lib/conduit/ on {len(targets)} server(s).\n\nAre you absolutely sure?"
        reply = QMessageBox.critical(self, "Confirm Full Reset", msg, 
                                     QMessageBox.Yes | QMessageBox.No, QMessageBox.No)

        if reply == QMessageBox.Yes:
            self.run_worker("reset")

    def create_item(self, s):
        """Creates a list item with a hidden IP key."""
        label = s['name'] if self.rad_name.isChecked() else s['ip']
        item = QListWidgetItem(label)
        item.setData(Qt.UserRole, s['ip']) 
        return item

    def sync_ui(self):
        """Updates display text for all items using the hidden IP key."""
        attr = 'name' if self.rad_name.isChecked() else 'ip'
        for lw in [self.pool, self.sel]:
            for i in range(lw.count()):
                it = lw.item(i)
                ip = it.data(Qt.UserRole)
                for s in self.server_data:
                    if s['ip'] == ip: 
                        it.setText(s[attr])
                        break
            lw.sortItems()

    def find_data_by_item(self, item):
        """
        CRITICAL FIX: This method MUST use data(Qt.UserRole).
        We ignore item.text() entirely because it changes based on radio buttons.
        """
        if not item: 
            return None
            
        # This is the hidden IP we stored during import/add
        hidden_ip = item.data(Qt.UserRole)
        
        for s in self.server_data:
            if s['ip'] == hidden_ip:
                return s
        return None

    def edit_srv(self):
        """Edits selected server based on hidden IP key."""
        it = self.pool.currentItem() or self.sel.currentItem()
        data = self.find_data_by_item(it)
        if not data:
            QMessageBox.information(self, "Edit", "Please select a server first.")
            return

        dlg = ServerDialog(self, data)
        if dlg.exec_() == QDialog.Accepted:
            new_info = dlg.get_data()
            
            # If IP changed, we need to update the hidden key too
            it.setData(Qt.UserRole, new_info['ip'])
            data.update(new_info)
            
            self.save()
            self.sync_ui() # Refresh all labels
            self.console.appendPlainText(f"[*] Updated: {new_info['name']}")

    def delete_srv(self):
        """Deletes selected servers using hidden IP key to ensure accuracy."""
        its = self.pool.selectedItems() + self.sel.selectedItems()
        if not its: return

        if QMessageBox.warning(self, "Delete", f"Delete {len(its)} server(s)?", 
                               QMessageBox.Yes|QMessageBox.No) == QMessageBox.Yes:
            for it in its:
                ip_key = it.data(Qt.UserRole)
                # Remove from UI
                it.listWidget().takeItem(it.listWidget().row(it))
                # Remove from Memory
                self.server_data = [s for s in self.server_data if s['ip'] != ip_key]
            
            self.save()
            self.console.appendPlainText(f"[-] Deleted {len(its)} server(s).")

    # --- Standard File/List Handlers ---

    def import_srv(self):
        path, _ = QFileDialog.getOpenFileName(self, "Open File", "", "Text (*.txt)")
        if path:
            self.current_path = path
            self.server_data = []
            self.pool.clear()
            self.sel.clear()
            
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    lines = f.readlines()
                    # Skip the header line
                    for line in lines[1:]:
                        line = line.strip()
                        if not line: continue # Skip empty lines
                        
                        parts = [p.strip() for p in line.split(',')]
                        
                        # Handle 4 parameters (name, ip, port, user) 
                        # or 5 parameters (name, ip, port, user, pass)
                        if len(parts) >= 4:
                            d = {
                                "name": parts[0],
                                "ip":   parts[1],
                                "port": parts[2],
                                "user": parts[3],
                                "pass": parts[4] if len(parts) > 4 else "" # Empty if 5th param missing
                            }
                            self.server_data.append(d)
                            self.pool.addItem(self.create_item(d))
                
                self.pool.sortItems()
                self.lbl_path.setText(os.path.basename(path))
                self.console.appendPlainText(f"[*] Successfully imported {len(self.server_data)} servers.")
            
            except Exception as e:
                QMessageBox.critical(self, "Import Error", f"Failed to read file: {str(e)}")

    def move_to_sel(self):
        for it in self.pool.selectedItems():
            self.sel.addItem(self.create_item(self.find_data_by_item(it)))
            self.pool.takeItem(self.pool.row(it))
        self.sel.sortItems()

    def move_to_pool(self):
        for it in self.sel.selectedItems():
            self.pool.addItem(self.create_item(self.find_data_by_item(it)))
            self.sel.takeItem(self.sel.row(it))
        self.pool.sortItems()

    def is_valid_ip(self, ip_str):
        try:
            ipaddress.ip_address(ip_str.strip())
            return True
        except ValueError:
            return False

    def add_srv(self):
        dlg = ServerDialog(self)
        if dlg.exec_() == QDialog.Accepted:
            d = dlg.get_data()
            
            # Extract and trim values
            name = d.get('name', '').strip()
            ip = d.get('ip', '').strip()
            port = d.get('port', '').strip()

            # 1. Validate Name
            if not name:
                QMessageBox.critical(self, "Invalid Name", "Server Name cannot be empty.")
                return
            
            # Check for commas as they would break your CSV servers.txt format
            if ',' in name:
                QMessageBox.critical(self, "Invalid Name", "Server Name cannot contain commas.")
                return

            # 2. Validate IP
            if not self.is_valid_ip(ip):
                QMessageBox.critical(self, "Invalid IP", f"'{ip}' is not a valid IP address.")
                return

            # 3. Validate Port
            try:
                port_num = int(port)
                if not (1 <= port_num <= 65535):
                    raise ValueError
            except ValueError:
                QMessageBox.critical(self, "Invalid Port", "Port must be a number between 1 and 65535.")
                return

            # If all checks pass:
            self.server_data.append(d)
            self.pool.addItem(self.create_item(d))
            self.save()
            self.pool.sortItems()
            self.console.appendPlainText(f"[OK] Added server: {name}")

    def save(self):
        if not self.current_path: 
            # If path is missing, default to servers.txt so saving works
            self.current_path = "servers.txt"
        
        # Update the UI label to show the filename
        # This fixes the "No file loaded" issue immediately after adding the first server
        self.lbl_path.setText(f"File: {os.path.basename(self.current_path)}")

        try:
            with open(self.current_path, 'w') as f:
                f.write("name, ip, port, user, password\n")
                for s in self.server_data:
                    # Using .get() prevents crashes if a key is missing
                    f.write(f"{s.get('name','')}, {s.get('ip','')}, {s.get('port','')}, {s.get('user','')}, {s.get('pass','')}\n")
            self.console.appendPlainText(f"[OK] Changes saved to {self.current_path}")
        except Exception as e:
            self.console.appendPlainText(f"[ERROR] Save failed: {e}")

    def run_worker(self, action):
        """
        Pulling targets based on the hidden UserRole IP key.
        """
        targets = []
        for i in range(self.sel.count()):
            item = self.sel.item(i)
            server_dict = self.find_data_by_item(item)
            if server_dict:
                targets.append(server_dict)
        
        if not targets: 
            QMessageBox.warning(self, "Action", "No servers in the Selected list.")
            return

        # Console Debug: Verify we have the right IPs before launching
        self.console.appendPlainText(f"\nTarget IPs: {', '.join([t['ip'] for t in targets])}")
        
        conf = {
            "clients": self.edit_clients.text(), 
            "bw": self.edit_bw.text(), 
            "update": self.chk_upd.isChecked()
        }
        
        self.console.appendPlainText(f"[>>>] {action.upper()} on {len(targets)} servers...")
        self.worker = ServerWorker(action, targets, conf)
        self.worker.log_signal.connect(lambda m: self.console.appendPlainText(m))
        self.worker.start()

    def check_initial_file(self):
        # We define our standard filename
        filename = "servers.txt"
        self.current_path = filename 

        if os.path.exists(filename):
            self.lbl_path.setText(f"File: {filename}")
            self.console.appendPlainText(f"[INFO] Found '{filename}' in current directory. Importing...")
            self.load_from_file(filename)
        else:
            self.lbl_path.setText("File: servers.txt (New)")
            self.console.appendPlainText("[NOTICE] No 'servers.txt' found. Your first server will create this file.")

    def remove_password_from_file(self,target_ip):
        filename = "servers.txt"
        if not os.path.exists(filename):
            return

        updated_lines = []

        with open(filename, 'r') as f:
            for line in f:
                line = line.strip()
                if not line: continue # Handle comments/empty lines
                    
                parts = [p.strip() for p in line.split(',')]

                # Basic requirement: name, ip, port, user
                if len(parts) >= 4:
                    # 1. IP Validation
                    if not self.is_valid_ip(parts[1]):
                        continue

                    # 2. Port Validation
                    try:
                        port_num = int(parts[2])
                        if not (1 <= port_num <= 65535):
                            raise ValueError
                    except ValueError:
                        continue

                if parts[1] == target_ip:
                    if parts[3] == "root":
                        # Reconstruct line without the password
                        # Format: name, ip, port, user, 
                        new_line = f"{parts[0]}, {parts[1]}, {parts[2]}, {parts[3]}, "
                        updated_lines.append(new_line)
                    else:
                        updated_lines.append(line)

                else:
                    updated_lines.append(line)

        with open(filename, "w") as f:
            f.write("\n".join(updated_lines) + "\n")

    def get_root_pwd_from_file(self,target_ip):
        filename = "servers.txt"
        if not os.path.exists(filename):
            return "", ""

        with open(filename, 'r') as f:
            for line in f:
                line = line.strip()
                if not line: continue # Handle comments/empty lines
                    
                parts = [p.strip() for p in line.split(',')]

                # Basic requirement: name, ip, port, user
                if len(parts) < 5: continue

                # 1. IP Validation
                if not self.is_valid_ip(parts[1]):
                    continue

                # 2. Port Validation
                try:
                    port_num = int(parts[2])
                    if not (1 <= port_num <= 65535):
                        raise ValueError
                except ValueError:
                    continue

                if parts[1] == target_ip:
                    if parts[3] == "root":
                        return parts[3],parts[4]
                    else:
                        return "", ""

        return "", ""

    def load_from_file(self, path):
        try:

            self.server_data.clear()
            self.pool.clear() 

            with open(path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line: continue # Handle comments/empty lines
                    
                    parts = [p.strip() for p in line.split(',')]

                    # Basic requirement: name, ip, port, user
                    if len(parts) >= 4:
                        # 1. IP Validation
                        if not self.is_valid_ip(parts[1]):
                            self.console.appendPlainText(f"[NOTICE] {parts[1]} is not a correct IP address. server {parts[0]} skipped.")
                            continue

                        # 2. Port Validation
                        try:
                            port_num = int(parts[2])
                            if not (1 <= port_num <= 65535):
                                raise ValueError
                        except ValueError:
                            self.console.appendPlainText(f"[NOTICE] Invalid Port {parts[2]} for {parts[0]}. Skipped.")
                            continue

                        # 3. Create Dictionary with Safe Password Check
                        d = {
                            'name': parts[0], 
                            'ip': parts[1], 
                            'port': str(port_num), # Keep as string for Fabric
                            'user': parts[3], 
                            'pass': parts[4] if len(parts) > 4 else ''
                        }                        

                        self.server_data.append(d)
                        self.pool.addItem(self.create_item(d))
            
            self.pool.sortItems()
            self.console.appendPlainText(f"[SUCCESS] {len(self.server_data)} servers imported.")
        except Exception as e:
            self.console.appendPlainText(f"[ERROR] Could not read file: {e}")


if __name__ == "__main__":
    app = QApplication(sys.argv); gui = ConduitGUI(); gui.show(); sys.exit(app.exec_())