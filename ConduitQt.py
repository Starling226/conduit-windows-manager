import sys
import os
import re
import statistics
from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QHBoxLayout, QPushButton, QLabel, QLineEdit, QInputDialog,
                             QCheckBox, QListWidget, QListWidgetItem, QPlainTextEdit, 
                             QFileDialog, QMessageBox, QFrame, QAbstractItemView, 
                             QRadioButton, QButtonGroup, QDialog, QFormLayout)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from fabric import Connection, Config

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
            
            # List of potential private keys to try
            potential_keys = [
#                os.path.join(home, ".ssh", "id_rsa"),
#                os.path.join(home, ".ssh", "id_ed25519"),
#                os.path.join(home, ".ssh", "id_dsa"),
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
                    res = run_cmd("systemctl is-active conduit")
                    state = "Active" if res.ok else "Inactive"
                    return f"[*] {s['name']} ({s['ip']}): {state}"

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

                # ... (rest of the start/stop/restart logic using run_cmd)
                
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
               "down": "0B", "uptime": "Offline", "mbps": "0.00", "mbps_val": 0.0}
        
        try:
            home = os.path.expanduser("~")
            key_path = os.path.join(home, ".ssh", "id_conduit")
            
            connect_kwargs = {
                "key_filename": key_path,
                "look_for_keys": False, 
                "allow_agent": False,
                "timeout": 15
            }
            cfg = Config(overrides={'run': {'pty': True}})

            with Connection(host=s['ip'], user=s['user'], port=int(s['port']), 
                            connect_kwargs=connect_kwargs, config=cfg) as conn:
                
                output = ""
                try:
                    # We reduce timeout slightly so the catch happens faster
                    cmd = "/opt/conduit/conduit service status -f"
                    result = conn.run(cmd, hide=True, timeout=10)
                    output = result.stdout
                except Exception as e:
                    # IMPORTANT: Even if it times out, result objects in Fabric 
                    # often store what they managed to read in the exception object!
                    if hasattr(e, 'result') and e.result.stdout:
                        output = e.result.stdout
                    else:
                        # Fallback: if we can't get it from the exception, the server is too slow
                        res["uptime"] = "Timeout"
                        return res

                if output:
                    clean = re.compile(r'\x1b\[[0-9;]*[a-zA-Z]').sub('', output)
                    
                    # If we see "Clients" or "Status", we have valid data regardless of the timeout error
                    if "Clients" in clean:
                        res["success"] = True
                        
                        def get_last(pat, txt):
                            found = re.findall(pat, txt, re.IGNORECASE)
                            return found[-1].strip() if found else "0"

                        res["clients"] = get_last(r"Clients:\s*(\d+)", clean)
                        res["up"] = get_last(r"Upload:\s*([\d\.]+ [TGMK]?B)", clean)
                        res["down"] = get_last(r"Download:\s*([\d\.]+ [TGMK]?B)", clean)
                        
                        uptime_match = re.search(r"Uptime:\s*([\dhm\s]+s)", clean)
                        res["uptime"] = uptime_match.group(1).strip() if uptime_match else "N/A"
                        
                        # Mbps logic
                        d_bytes = self.parse_to_bytes(res["down"])
                        total_sec = self.uptime_to_seconds(res["uptime"])
                        if total_sec > 0:
                            mbps = (d_bytes * 8) / total_sec / 10**6
                            res["mbps_val"] = mbps
                            res["mbps"] = f"{mbps:.2f}"
        except Exception as e:
            res["uptime"] = "Conn Error"
            
        return res

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
        # 1. Main Table Generation (The header and server rows)
        width = 83
        head = f"│ {'Name/IP':<20} │ {'Clients':<7} │ {'Up':<9} │ {'Down':<9} │ {'Uptime':<14} │ {'Mbps':<6} │\n"
        sep = "├" + "─"*22 + "┼" + "─"*9 + "┼" + "─"*11 + "┼" + "─"*11 + "┼" + "─"*16 + "┼" + "─"*8 + "┤\n"
        
        body = ""
        valid_results = [r for r in results if r["success"]]
        
        for r in results:
            status = "✓" if r["success"] else "✗"
            body += f"│ {status} {r['label'][:18]:<18} │ {r['clients']:<7} │ {r['up']:<9} │ {r['down']:<9} │ {r['uptime']:<14} │ {r['mbps']:<6} │\n"
        
        main_table = f"┌" + "─"*width + "┐\n" + head + sep + body + "└" + "─"*width + "┘"

        # 2. Analytics Summary Logic (Integrated from your script)
        if not valid_results:
            return main_table + "\n[!] No active data to calculate analytics."

        # Set up timestamp for Iran Time (UTC+3:30)
        ts = (datetime.now(timezone.utc) + timedelta(hours=3, minutes=30)).strftime('%Y-%m-%d %H:%M:%S')
        
        total_clients = sum([int(r["clients"]) for r in valid_results if r["clients"].isdigit()])
        
        out = []
        out.append(f"\n--- Analytics Summary (Iran Time: {ts}) ---")
        out.append(f"Total number of Clients across all servers: {total_clients}\n")
        
        # Header for the Metric Table
        out.append(f"{'Metric':<12} │ {'Mean':<12} │ {'Median':<12} │ {'Min':<12} │ {'Max':<12}")
        sep_line = f"{'─'*13}┼{'─'*14}┼{'─'*14}┼{'─'*14}┼{'─'*14}"
        out.append(sep_line)

        # Stat Row Helper function
        def get_stat_row(label, data_list, is_bytes=False):
            if not data_list: return ""
            avg_val = statistics.mean(data_list)
            med_val = statistics.median(data_list)
            min_val = min(data_list)
            max_val = max(data_list)
            
            if is_bytes:
                return f"{label:<12} │ {self.format_bytes(avg_val):<12} │ {self.format_bytes(med_val):<12} │ {self.format_bytes(min_val):<12} │ {self.format_bytes(max_val):<12}"
            if label == "Clients":
                return f"{label:<12} │ {int(round(avg_val)):<12} │ {int(round(med_val)):<12} │ {int(min_val):<12} │ {int(max_val):<12}"
            # Avg Mbps
            return f"{label:<12} │ {avg_val:<12.2f} │ {med_val:<12.2f} │ {min_val:<12.2f} │ {max_val:<12.2f} Mbps"

        # Data extraction for the Metric table
        clients_list = [int(r["clients"]) for r in valid_results if str(r["clients"]).isdigit()]
        ups = [self.parse_to_bytes(r["up"]) for r in valid_results]
        downs = [self.parse_to_bytes(r["down"]) for r in valid_results]
        mbps_list = [r["mbps_val"] for r in valid_results]

        # Append the calculated rows
        out.append(get_stat_row("Clients", clients_list))
        out.append(get_stat_row("Upload", ups, True))
        out.append(get_stat_row("Download", downs, True))
        out.append(get_stat_row("Avg Mbps", mbps_list))

        return main_table + "\n" + "\n".join(out)

    def generate_table2(self, results):
        # Slightly wider name column for Linux paths/long names
        head = f"│ {'Name/IP':<20} │ {'Clients':<7} │ {'Up':<9} │ {'Down':<9} │ {'Uptime':<14} │ {'Mbps':<6} │\n"
        sep = "├" + "─"*20 + "┼" + "─"*9 + "┼" + "─"*11 + "┼" + "─"*11 + "┼" + "─"*16 + "┼" + "─"*8 + "┤\n"
        body = ""
        total_c = 0
        for r in results:
            status = "✓" if r["success"] else "✗"
            body += f"│ {status} {r['label'][:18]:<18} │ {r['clients']:<7} │ {r['up']:<9} │ {r['down']:<9} │ {r['uptime']:<14} │ {r['mbps']:<8} │\n"
            if r["success"]: total_c += int(r["clients"])
        
        w = 83
        return f"┌" + "─"*w + "┐\n" + head + sep + body + "└" + "─"*w + "┘\nTOTAL CLIENTS: " + str(total_c)

class DeployWorker(QThread):
    log_signal = pyqtSignal(str)

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
            config = Config(overrides={'run': {'pty': True}, 'timeouts': {'connect': 20}})
            conn_params = {
                "password": self.params['password'],
                "look_for_keys": False,
                "allow_agent": False
            }

            with Connection(host=s['ip'], user=self.params['user'], port=int(s['port']), 
                            connect_kwargs=conn_params, config=config) as conn:
                
                # 1. Key Injection
                conn.run("mkdir -p ~/.ssh && chmod 700 ~/.ssh", hide=True)
                conn.run(f'echo "{pub_key}" >> ~/.ssh/authorized_keys', hide=True)
                conn.run("chmod 600 ~/.ssh/authorized_keys", hide=True)

                # 2. Cleanup & Install Dependencies
                conn.run("systemctl stop conduit", warn=True, hide=True)
                conn.run("rm -f /opt/conduit/conduit", warn=True, hide=True)
                conn.run("mkdir -p /opt/conduit", hide=True)

                pkg_cmd = "dnf install wget firewalld curl -y" if conn.run("command -v dnf", warn=True, hide=True).ok else "apt-get update -y && apt-get install wget firewalld curl -y"
                conn.run(pkg_cmd, hide=True)

                # 3. Download & Install Binary
                url = "https://github.com/ssmirr/conduit/releases/download/e421eff/conduit-linux-amd64"
                conn.run(f"curl -L -o /opt/conduit/conduit {url}", hide=True)
                conn.run("chmod +x /opt/conduit/conduit")
                conn.run("/opt/conduit/conduit service install", hide=True)

                # 4. Configure Service
                svc = "/etc/systemd/system/conduit.service"
                cmd = f"/opt/conduit/conduit start --max-clients {self.params['clients']} --bandwidth {self.params['bw']} --data-dir /var/lib/conduit"
                conn.run(f"sed -i 's|^ExecStart=.*|ExecStart={cmd}|' {svc}")
                
                # 5. Start
                conn.run("systemctl daemon-reload && systemctl enable conduit && systemctl start conduit", hide=True)
                
                return f"[OK] {s['ip']} successfully deployed."
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

    def init_ui(self):
        central = QWidget(); self.setCentralWidget(central)
        layout = QVBoxLayout(central)

        # UI Components Setup (Labels, Edits, Frames)
        file_box = QHBoxLayout()
        self.btn_import = QPushButton("Import servers.txt")
        self.lbl_path = QLabel("No file loaded")
        file_box.addWidget(self.btn_import); file_box.addWidget(self.lbl_path); file_box.addStretch()
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
        self.console.setStyleSheet("background: #1e1e1e; color: #00ff00; font-family: Consolas;")
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
        targets = [self.find_data_by_item(self.sel.item(i)) for i in range(self.sel.count())]
        if not targets:
            QMessageBox.warning(self, "Deployment", "No servers selected.")
            return

        # NEW: Run the validation check
        validated = self.get_validated_inputs()
        if not validated:
            return  # Stop here if validation failed

        # Existing Warning Message...
        warning_text = (
            "WARNING: PRE-EXISTING INSTALLATION DETECTED?\n\n"
            "If these are existing Conduit servers, this process will:\n"
            "1. STOP the current conduit service.\n"
            "2. REMOVE the existing conduit binary.\n"
            "3. INSTALL a fresh copy as ROOT and reset the service configuration.\n\n"
            f"Config: {validated['clients']} Clients | {validated['bw']} Mbps\n\n"
            "Proceed only if you have the root password for these servers.\n"
            "Are you absolutely sure you want to proceed?"
        )
        
        reply = QMessageBox.critical(self, "Confirm Fresh Deployment", warning_text, 
                                     QMessageBox.Yes | QMessageBox.No, QMessageBox.No)

        if reply != QMessageBox.Yes:
            return

        pwd, ok = QInputDialog.getText(self, "Root Authentication", "Enter Root Password:", QLineEdit.Password)
        if not ok or not pwd:
            return

        params = {
            "password": pwd,
            "user": "root",
            "clients": validated['clients'], 
            "bw": validated['bw']            
        }

        # UI Feedback
        self.btn_deploy.setEnabled(False)
        self.btn_deploy.setText("Deploying...")
        
        self.console.appendPlainText(f"\n[>>>] INITIATING FRESH ROOT DEPLOYMENT ON {len(targets)} SERVER(S)...")
        
        self.deploy_thread = DeployWorker(targets, params)
        self.deploy_thread.log_signal.connect(lambda m: self.console.appendPlainText(m))
        
        # Reset button state when done
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

    def add_srv(self):
        if not self.current_path: return
        dlg = ServerDialog(self)
        if dlg.exec_() == QDialog.Accepted:
            d = dlg.get_data()
            self.server_data.append(d); self.pool.addItem(self.create_item(d))
            self.save(); self.pool.sortItems()

    def save(self):
        if not self.current_path: return
        with open(self.current_path, 'w') as f:
            f.write("name, ip, port, user, password\n")
            for s in self.server_data:
                f.write(f"{s['name']}, {s['ip']}, {s['port']}, {s['user']}, {s['pass']}\n")

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

if __name__ == "__main__":
    app = QApplication(sys.argv); gui = ConduitGUI(); gui.show(); sys.exit(app.exec_())