import sys
import os
import re
import time
import gzip
import io
import platform
import statistics
import ipaddress
import numpy as np
from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QHBoxLayout, QPushButton, QLabel, QLineEdit, QInputDialog,
                             QCheckBox, QListWidget, QListWidgetItem, QPlainTextEdit, 
                             QFileDialog, QMessageBox, QFrame, QAbstractItemView, 
                             QRadioButton, QButtonGroup, QDialog, QFormLayout, 
                             QTableWidgetItem, QTableWidget, QHeaderView)

from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer, QObject, QRunnable, QThreadPool
from PyQt5.QtGui import QFont
from PyQt5.QtGui import QColor, QBrush
from fabric import Connection, Config
import pyqtgraph as pg
from pyqtgraph import DateAxisItem
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
from PyQt5.QtGui import *

# --- PLATFORM SPECIFIC FIXES ---
if platform.system() == "Darwin":  # Darwin is the internal name for macOS
    # Fix for tiny fonts on Retina displays
    QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)
    print("[INFO] macOS High-DPI Scaling Enabled")

CONDUIT_URL = "https://github.com/ssmirr/conduit/releases/download/2fd31d4/conduit-linux-amd64"
APP_VERSION = "2.1.1"

class LogFetcherSignals(QObject):
    """Signals for individual thread status."""
    finished = pyqtSignal(str) # Emits IP when done

class ReportFetcher(QRunnable):
    def __init__(self, server):
        super().__init__()
        self.server = server
        # Reuse the existing signal class
        self.signals = LogFetcherSignals()

    def run(self):
        ip = self.server['ip']
        try:
            current_year = datetime.now().year
            remote_path = f"/opt/conduit/{current_year}-conduit.log"
            
            # Simple stream and compress
            cmd = f"cat {remote_path} | gzip -c"

            text_buffer = io.StringIO()
            home = os.path.expanduser("~")
            key_path = os.path.join(home, ".ssh", "id_conduit")

            connect_kwargs = {
                "key_filename": [key_path], 
                "timeout": 10,
                "look_for_keys": False, 
                "allow_agent": False  
            }

            with Connection(host=ip, user=self.server['user'], port=int(self.server['port']), connect_kwargs=connect_kwargs) as conn:
                conn.run(cmd, hide=True, out_stream=text_buffer, encoding='latin-1')
                
                compressed_bytes = text_buffer.getvalue().encode('latin-1')
                
                if not compressed_bytes:
                    print(f"FAILED: No data in {remote_path} for {ip}")
                    return

                raw_bytes = gzip.decompress(compressed_bytes)
                decoded_text = raw_bytes.decode('utf-8')

                os.makedirs("server_report_logs", exist_ok=True)
                # Saving as .raw so the Visualizer knows it needs processing
                with open(f"server_report_logs/{ip}.raw", "w") as f:
                    f.write(decoded_text)
                            
        except Exception as e:
            print(f"CRITICAL ERROR for {ip}: {e}")
        finally:
            # Emitting the finished signal regardless of success/failure
            self.signals.finished.emit(ip)

class LogFetcher(QRunnable):
    def __init__(self, server, days):
        super().__init__()
        self.server = server
        self.days = days
        self.signals = LogFetcherSignals()

    def run(self):
        ip = self.server['ip']
        try:
            # 1. Fetch only relevant lines from journal

            cmd = (
                f"journalctl -u conduit.service --since '{self.days} days ago' --no-pager -o short-iso | "
                f"grep '[STATS]' | "
                f"sed 's/.*conduit\[[0-9]*\]: //' | "
                f"gzip -c"
            )

            text_buffer = io.StringIO()

            home = os.path.expanduser("~")
            key_path = os.path.join(home, ".ssh", "id_conduit")

            connect_kwargs = {
                "key_filename": [key_path], 
                "timeout": 10,
                "look_for_keys": False,  # STOP searching ~/.ssh/ for other keys
                "allow_agent": False     # STOP trying to talk to Pageant/ssh-agent
            }


            with Connection(host=ip, user=self.server['user'], port=int(self.server['port']), connect_kwargs=connect_kwargs) as conn:
                conn.run(cmd, hide=True, out_stream=text_buffer, encoding='latin-1')
                compressed_bytes = text_buffer.getvalue().encode('latin-1')
                if not compressed_bytes:
                    print(f"FAILED: server_logs/{ip}.raw")
                    return

                raw_bytes = gzip.decompress(compressed_bytes)
                decoded_text = raw_bytes.decode('utf-8')
                with open(f"server_logs/{ip}.raw", "w") as f:
                    f.write(decoded_text)
                
                            
        except Exception as e:
            print(f"CRITICAL ERROR for {ip}: {e}")
        finally:
            self.signals.finished.emit(ip)

    def parse_to_bytes(self, size_str):
        """Helper to convert '10.5 GB' to raw integer bytes."""
        units = {"B": 1, "KB": 10**3, "MB": 10**6, "GB": 10**9, "TB": 10**12}
        try:
            number, unit = size_str.split()
            return int(float(number) * units.get(unit.upper(), 1))
        except:
            return 0


class HistoryWorker(QThread):
    """Manages the pool of LogFetchers."""
    all_finished = pyqtSignal()
    progress = pyqtSignal(int) # Percentage of servers completed

    def __init__(self, servers, days):
        super().__init__()
        self.servers = servers
        self.days = days
#        self.completed_count = 0

    def run(self):
        if not os.path.exists("server_logs"):
            os.makedirs("server_logs")

        pool = QThreadPool.globalInstance()
        # Set max threads to number of servers or a reasonable limit (e.g., 20)
        pool.setMaxThreadCount(5)

        total = len(self.servers)
        for s in self.servers:
            fetcher = LogFetcher(s, self.days)
#            fetcher.signals.finished.connect(self.on_one_finished)
            pool.start(fetcher)

        # Wait for pool to finish
        pool.waitForDone()
        self.all_finished.emit()

    def on_one_finished(self, ip):
        self.completed_count += 1
        percent = int((self.completed_count / len(self.servers)) * 100)
        self.progress.emit(percent)

class ReportWorker(QThread):
    """Manages the pool of LogFetchers."""
    all_finished = pyqtSignal()
    progress = pyqtSignal(int) # Percentage of servers completed

    def __init__(self, servers):
        super().__init__()
        self.servers = servers

#        self.completed_count = 0

    def run(self):
        if not os.path.exists("server_logs"):
            os.makedirs("server_logs")

        pool = QThreadPool.globalInstance()
        # Set max threads to number of servers or a reasonable limit (e.g., 20)
        pool.setMaxThreadCount(5)

        total = len(self.servers)
        for s in self.servers:
            fetcher = ReportFetcher(s)
#            fetcher.signals.finished.connect(self.on_one_finished)
            pool.start(fetcher)

        # Wait for pool to finish
        pool.waitForDone()
        self.all_finished.emit()

    def on_one_finished(self, ip):
        self.completed_count += 1
        percent = int((self.completed_count / len(self.servers)) * 100)
        self.progress.emit(percent)

class NumericTableWidgetItem(QTableWidgetItem):
    def __init__(self, text, sort_value):
        super().__init__(text)
        self.sort_value = sort_value

    def __lt__(self, other):
        if isinstance(other, NumericTableWidgetItem):
            return self.sort_value < other.sort_value
        return super().__lt__(other)

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


class AutoStatsWorker(QThread):
    # This signal sends the raw list of dictionaries to update_stats_table
    stats_ready = pyqtSignal(list)

    def __init__(self, targets, display_mode, time_window):
        super().__init__()
        self.targets = targets
        self.display_mode = display_mode
        self.time_window = time_window # Format: "X minutes ago"

    def run(self):
        results = []
        # Using 15 workers just like your StatsWorker for fast parallel fetching
        with ThreadPoolExecutor(max_workers=15) as executor:
            futures = [executor.submit(self.get_stats, s) for s in self.targets]
            for f in as_completed(futures):
                results.append(f.result())
        
        # Sort by IP or clients if preferred, then emit to GUI
        self.stats_ready.emit(results)

    def get_stats(self, s):
        res = {"ip": s['ip'], "success": False, "clients": "0", "up_val": "0 B", "down_val": "0 B"}
        
        try:
            home = os.path.expanduser("~")
            key_path = os.path.join(home, ".ssh", "id_conduit")
            connect_kwargs = {"key_filename": [key_path], "look_for_keys": False, "allow_agent": False, "timeout": 5}

            with Connection(host=s['ip'], user=s['user'], port=int(s['port']), connect_kwargs=connect_kwargs) as conn:
                # 1. Check if the service is actually RUNNING right now
                status_check = conn.run("systemctl is-active conduit.service", hide=True, warn=True)
                is_running = status_check.stdout.strip() == "active"

                if not is_running:
                    res["success"] = False
                    res["clients"] = "Stopped"
                    return res

                # 2. If running, get the logs for the requested window
                cmd = f"journalctl -u conduit.service --since '{self.time_window}' -o cat | grep -F '[STATS]'"
                result = conn.run(cmd, hide=True, timeout=12)
                output = result.stdout.strip()

                if output:
                    lines = output.splitlines()
                    # Using your regex pattern...
                    pattern = re.compile(r"\[STATS\].*?(?:Clients|Connected):\s*(\d+)\s*\|\s*Up:\s*([\d\.]+)\s*([TGMK]?B)\s*\|\s*Down:\s*([\d\.]+)\s*([TGMK]?B)")
                    
                    data_points = []
                    for line in lines:
                        m = pattern.search(line)
                        if m:
                            data_points.append({
                                'c': int(m.group(1)),
                                'u': self.parse_to_bytes(f"{m.group(2)} {m.group(3)}"),
                                'd': self.parse_to_bytes(f"{m.group(4)} {m.group(5)}")
                            })

                    if data_points:
                        res["success"] = True
                        client_counts = [d['c'] for d in data_points if d['c'] > 0]
                        if client_counts:
                            avg_clients = sum(client_counts) / len(client_counts)

                        first, last = data_points[0], data_points[-1]

                        res["clients"] = str(int(round(avg_clients)))
                        res["up_val"] = self.format_bytes(max(0, last['u'] - first['u']))
                        res["down_val"] = self.format_bytes(max(0, last['d'] - first['d']))
                else:
                    res["success"] = False
                    res["clients"] = "No Data"
                    
        except Exception:
            res["clients"] = "Offline"
            
        return res

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

    def format_bytes(self, b):
        if b == 0: return "0 B"
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if b < 1024: return f"{b:.2f} {unit}"
            b /= 1024
        return f"{b:.2f} PB"

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

                def get_conduit_stats():
                    service_path = "/etc/systemd/system/conduit.service"
    
                    # This command searches the ExecStart line for the flags and returns just the values
                    cmd = f"grep 'ExecStart' {service_path} | grep -oP '(?<=--max-clients )[0-9]+|(?<=--bandwidth )[0-9.]+'"
    
                    result = run_cmd(cmd)
    
                    if result and result.ok:
                        # result.stdout will contain two lines: max-clients and bandwidth
                        output = result.stdout.strip().split('\n')
                        if len(output) >= 2:
                            max_clients = output[0]
                            bandwidth = output[1]
#                            print(f"Current Config: {max_clients} Clients @ {bandwidth} Mbps")
                            return f"max-clients: {max_clients} bandwidth: {bandwidth} Mbps"
    
                    print("Failed to parse conduit service file.")
                    return f"max-clients: None bandwidth: None Mbps"

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
                    
                    output = f"--- STATUS: {current_status} ---\n{get_conduit_stats()}\n{journal_logs}"
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

        server_count = len(valid_results)
        total_up_all = sum(ups)
        total_down_all = sum(downs)
        total_up_1h = sum([self.parse_to_bytes(r["up_1h"]) for r in valid_results])
        total_down_1h = sum([self.parse_to_bytes(r["down_1h"]) for r in valid_results])

        out = []
        out.append(f"\n--- Analytics Summary (Iran Time: {ts}) ---")
        out.append(f"Total Average Clients across all servers: {total_clients}\n")
        
        # Printing the specific totals you requested
        out.append(f"\nTotal UP across {server_count} servers: {self.format_bytes(total_up_all)} | Total UP in last one hour: {self.format_bytes(total_up_1h)}")
        out.append(f"Total Down across {server_count} servers: {self.format_bytes(total_down_all)} | Total DOWN in last one hour: {self.format_bytes(total_down_1h)}\n")

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

    def __init__(self, action, targets, params):
        super().__init__()
        self.targets = targets
        self.params = params # password, max_clients, bandwidth, user
        self.action = action

    def run(self):
        # Read the public key once
        home = os.path.expanduser("~")
        pub_key_path = os.path.join(home, ".ssh", "id_conduit.pub")
        
        if not os.path.exists(pub_key_path):
            self.log_signal.emit(f"[ERROR] Public key not found at: {pub_key_path}")
            return

        with open(pub_key_path, "r") as f:
            pub_key_content = f.read().strip()

        if self.action == "deploy":
            with ThreadPoolExecutor(max_workers=5) as executor:
                futures = [executor.submit(self.deploy_task, s, pub_key_content) for s in self.targets]
                for f in as_completed(futures):
                    self.log_signal.emit(f.result())

        elif self.action == "upgrade":
            with ThreadPoolExecutor(max_workers=5) as executor:
                futures = [executor.submit(self.upgrade_task, s) for s in self.targets]
                for f in as_completed(futures):
                    self.log_signal.emit(f.result())
        else:
            self.log_signal.emit(f"[WARNING] No action is taken: {s['ip']}")
            return

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
                
                # 6. Download Stats Script from GitHub
                # We use the 'raw' GitHub URL to get the actual code, not the HTML page
                stats_script_url = "https://raw.githubusercontent.com/Starling226/conduit-manager/main/get_conduit_stat.py"
                conn.run(f"curl -L -o /opt/conduit/get_conduit_stat.py {stats_script_url}", hide=True)
                conn.run("chmod +x /opt/conduit/get_conduit_stat.py")

                # 7. Setup Cronjob (Idempotent: prevents duplicate entries)
                cron_cmd = "0 * * * * /usr/bin/python3 /opt/conduit/get_conduit_stat.py >> /opt/conduit/cron_sys.log 2>&1"
                # This command checks if the job exists; if not, it adds it to the crontab
                conn.run(f'(crontab -l 2>/dev/null | grep -Fv "/opt/conduit/get_conduit_stat.py" ; echo "{cron_cmd}") | crontab -', hide=True)

                if pwd:
                    self.remove_password_signal.emit(s['ip'])

                return f"[OK] {s['ip']} successfully deployed (Manual Service Config)."
        except Exception as e:
            return f"[ERROR] {s['ip']} failed: {str(e)}"

    def upgrade_task(self, s):
        try:

            home = os.path.expanduser("~")
            key_path = os.path.join(home, ".ssh", "id_conduit")
        
            conn_params = {
                "timeout": 10,
                "banner_timeout": 20
            }

            try:
                # Automatically extract 'version' from the URL
                version_tag = CONDUIT_URL.split('/')[-2]
            except (NameError, IndexError):
                version_tag = "Unknown"
                        
            conn_params["key_filename"] = [key_path]
            conn_params["look_for_keys"] = False
            conn_params["allow_agent"] = False            
            
            pwd = s.get('pass') 
            
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
                
                
                # --- NEW: VERSION CHECK LOGIC ---
                self.log_signal.emit(f"[{s['ip']}] Checking current version...")
                v_check = conn.run("/opt/conduit/conduit --version", hide=True, warn=True)
                
                if v_check.ok:
                    # Extract the hash from "conduit version e421eff"
                    current_version = v_check.stdout.strip().split()[-1]
                    
                    if current_version == version_tag:
                        return f"[SKIP] {s['ip']} is already running the latest version ({version_tag})."
                # --------------------------------

                # 2. Cleanup & Stop (Only runs if version is different or binary missing)
                self.log_signal.emit(f"[{s['ip']}] Upgrading {current_version} -> {version_tag}...")

                conn.run("systemctl stop conduit", warn=True, hide=True)
                time.sleep(2)
                conn.run("rm -f /opt/conduit/conduit", warn=True, hide=True)

                # 3. Download Binary
                conn.run(f"curl -L -o /opt/conduit/conduit {CONDUIT_URL}", hide=True)                
                conn.run("chmod +x /opt/conduit/conduit")

                # 5. Start
                conn.run("systemctl start conduit", hide=True)                
                
                stats_script_url = "https://raw.githubusercontent.com/Starling226/conduit-manager/main/get_conduit_stat.py"
                conn.run(f"curl -L -o /opt/conduit/get_conduit_stat.py {stats_script_url}", hide=True)
                conn.run("chmod +x /opt/conduit/get_conduit_stat.py")

                # 7. Setup Cronjob (Idempotent: prevents duplicate entries)
                cron_cmd = "0 * * * * /usr/bin/python3 /opt/conduit/get_conduit_stat.py >> /opt/conduit/cron_sys.log 2>&1"
                # This command checks if the job exists; if not, it adds it to the crontab
                conn.run(f'(crontab -l 2>/dev/null | grep -Fv "/opt/conduit/get_conduit_stat.py" ; echo "{cron_cmd}") | crontab -', hide=True)

                return f"[OK] {s['ip']} successfully upgraded to conduit version {version_tag}."
        except Exception as e:
            return f"[ERROR] {s['ip']} failed: {str(e)}"

# --- 3. Main GUI Window ---
class ConduitGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Conduit Manager")
        self.setMinimumSize(1100, 800)
        self.server_data = [] 
        self.current_path = ""

        # Timer for Auto-Refresh
        self.refresh_timer = QTimer()
        self.refresh_timer.timeout.connect(self.run_auto_stats)

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

# Combine them or stack them

        version_text = f"Manager: v{APP_VERSION} | Conduit: {version_tag}"
        self.lbl_version = QLabel(version_text)
        self.lbl_version.setStyleSheet("color: gray; font-style: italic; font-size: 11px;")

#        self.lbl_version = QLabel(f"Conduit Version: {version_tag}")
#        self.lbl_version.setStyleSheet("color: gray; font-style: italic; font-size: 11px;")
        
        # This stretch pushes everything after it to the right wall
#        file_box.addStretch(1) 
        
        file_box.addWidget(self.lbl_version)
        
        layout.addLayout(file_box)

        cfg_frame = QFrame(); cfg_frame.setFrameShape(QFrame.StyledPanel)
        cfg_lay = QHBoxLayout(cfg_frame)

    # Helper to apply consistent width for the 4 entries
        def set_fixed_entry(widget):
            widget.setFixedWidth(80)
            return widget

        cfg_lay.addWidget(QLabel("Max Clients:"));
#        self.edit_clients = QLineEdit("225")
        self.edit_clients = set_fixed_entry(QLineEdit("225"))
        cfg_lay.addWidget(self.edit_clients)

#        cfg_lay.addWidget(QLabel("Mbps:"));
        cfg_lay.addWidget(QLabel("Bandwidth (Mbps):"));
#        self.edit_bw = QLineEdit("40.0")
        self.edit_bw = set_fixed_entry(QLineEdit("40.0"))
        cfg_lay.addWidget(self.edit_bw)

        # Field 3: Log Window (The new free parameter - in minutes)
        cfg_lay.addWidget(QLabel("Log Win(min):")); 
        self.edit_window = set_fixed_entry(QLineEdit("60"))
        self.edit_window.setToolTip("Lookback window for logs (1-60 minutes). Used in Status Table")
        cfg_lay.addWidget(self.edit_window)


# --- REFRESH ENTRY & BUTTON ---
        cfg_lay.addSpacing(15)
        cfg_lay.addWidget(QLabel("Refresh (min):"))
        self.edit_refresh = set_fixed_entry(QLineEdit("5"))
        self.edit_refresh.setToolTip("Refresh interval. Used in Status Table")
#        self.edit_refresh = QLineEdit("5")
#        self.edit_refresh.setFixedWidth(35)
        self.btn_refresh_now = QPushButton("↻") 
        self.btn_refresh_now.setFixedWidth(30)
        self.btn_refresh_now.setToolTip("Refresh Live Monitor Now")
        cfg_lay.addWidget(self.edit_refresh)
        cfg_lay.addWidget(self.btn_refresh_now)
        self.edit_refresh.textChanged.connect(self.update_timer_interval)
        self.btn_refresh_now.clicked.connect(self.run_auto_stats)
        # ------------------------------

        cfg_lay.addSpacing(10)
        self.chk_upd = QCheckBox("Apply Config Changes")
        self.chk_upd.setToolTip("Checked and Click on Re-Start (if server is running) or Start to update the Max Clients and Bandwidth")
        cfg_lay.addWidget(self.chk_upd)
        self.rad_name = QRadioButton("Display Name")
        self.rad_ip = QRadioButton("Display IP")
        self.rad_name.setChecked(True)
        cfg_lay.addWidget(self.rad_name)
        cfg_lay.addWidget(self.rad_ip)
        cfg_lay.addStretch(1)

        layout.addWidget(cfg_frame)

        lists_lay = QHBoxLayout()
        self.pool = QListWidget(); self.sel = QListWidget()
        for l in [self.pool, self.sel]: l.setSelectionMode(QAbstractItemView.ExtendedSelection)
        
        # --- NEW LIVE MONITOR TABLE ---
        self.stats_table = QTableWidget(0, 4)
        self.stats_table.setHorizontalHeaderLabels(["IP Address", "Avg Clients (1h)", "Up (1h)", "Down (1h)"])
#        self.stats_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)

        header = self.stats_table.horizontalHeader()
        header.setStretchLastSection(True)

        header.setSectionResizeMode(0, QHeaderView.Stretch) # IP takes remaining space
        header.setSectionResizeMode(1, QHeaderView.Fixed)
        header.setSectionResizeMode(2, QHeaderView.Fixed)
        header.setSectionResizeMode(3, QHeaderView.Fixed)
        
        self.stats_table.setColumnWidth(1, 110)  # Reduced Avg Clients
        self.stats_table.setColumnWidth(2, 110) # Reduced Up
        self.stats_table.setColumnWidth(3, 110) # Reduced Down

        self.stats_table.setStyleSheet("background-color: #f8f9fa; gridline-color: #dee2e6;")
        self.stats_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.stats_table.setSelectionBehavior(QAbstractItemView.SelectRows)
#        self.stats_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        # ------------------------------
        
        # --- LIVE MONITOR TABLE (Right Panel) ---
#        self.stats_table = QTableWidget(0, 4)
        # ... (rest of table setup, including sorting enabled) ...
        
# --- FOOTER FOR TOTALS & TIMESTAMP ---
        self.footer_frame = QFrame()
        self.footer_frame.setFixedHeight(35) # Slightly taller for better padding
        self.footer_frame.setStyleSheet("background-color: #f1f2f6; border-top: 1px solid #dcdcdc;")
        footer_lay = QHBoxLayout(self.footer_frame)
        footer_lay.setContentsMargins(15, 0, 15, 0)

        # New Timestamp Label (Left Side)
        self.lbl_last_updated = QLabel("Last Sync: Never")
        self.lbl_last_updated.setStyleSheet("color: #7f8c8d; font-style: italic; font-size: 11px;")
        footer_lay.addWidget(self.lbl_last_updated)

        footer_lay.addStretch(1) # Pushes the stats to the right

        # Metric Labels (Right Side)
        self.lbl_total_clients = QLabel("Clients: 0")
        self.lbl_total_up = QLabel("Up: 0 B")
        self.lbl_total_down = QLabel("Down: 0 B")
        
        for lbl in [self.lbl_total_clients, self.lbl_total_up, self.lbl_total_down]:
            lbl.setStyleSheet("font-weight: bold; color: #2c3e50;")
            lbl.setFixedWidth(130)
            footer_lay.addWidget(lbl)

        layout.addWidget(self.stats_table)
        layout.addWidget(self.footer_frame)

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
        
        lists_lay.addWidget(self.pool,1); lists_lay.addLayout(mid_btns); lists_lay.addWidget(self.sel,1)
        lists_lay.addWidget(self.stats_table, 2) # Giving the table more space
        layout.addLayout(lists_lay)

        ctrl_lay = QHBoxLayout()
        self.btn_start = QPushButton("Start"); 
        self.btn_start.setStyleSheet("background-color: #2c3e50; color: white; font-weight: bold;")

        self.btn_stop = QPushButton("Stop")
        self.btn_stop.setStyleSheet("background-color: #2c3e50; color: white; font-weight: bold;")
        
        self.btn_re = QPushButton("Re-Start");        
        self.btn_re.setStyleSheet("background-color: #2c3e50; color: white; font-weight: bold;")
        self.btn_re.setToolTip("Use Restart if server is already running.")

        self.btn_reset = QPushButton("Reset")
        self.btn_reset.setStyleSheet("background-color: #2c3e50; color: white; font-weight: bold;")

        self.btn_stat = QPushButton("Status");
        self.btn_stat.setStyleSheet("background-color: #2c3e50; color: white; font-weight: bold;")

        self.btn_quit = QPushButton("Quit")
        self.btn_reset.setToolTip("Use if clients not added after hours or server waiting to connect.")        

        self.btn_stats = QPushButton("Statistics")
        self.btn_stats.setStyleSheet("background-color: #2c3e50; color: white; font-weight: bold;")

        self.btn_report = QPushButton("Report")
        self.btn_report.setStyleSheet("background-color: #27ae60; color: white; font-weight: bold;")
        self.btn_report.clicked.connect(self.open_report)
        cfg_lay.addWidget(self.btn_report)

        self.btn_visualize = QPushButton("Traffic")
        self.btn_visualize.setStyleSheet("background-color: #8e44ad; color: white; font-weight: bold;")
        self.btn_visualize.clicked.connect(self.open_visualizer)
        cfg_lay.addWidget(self.btn_visualize)

        self.btn_deploy = QPushButton("Deploy")
        self.btn_deploy.setStyleSheet("background-color: #e67e22; color: white; font-weight: bold;")            

        self.btn_upgrade = QPushButton("Upgrade")
#        self.btn_upgrade.setStyleSheet("background-color: #27ae60; color: white; font-weight: bold;")
#        self.btn_upgrade.setStyleSheet("background-color: #8e44ad; color: white; font-weight: bold;")
        self.btn_upgrade.setStyleSheet("background-color: #2980b9; color: white; font-weight: bold;")
        self.btn_upgrade.setToolTip("Upgrade the conduit to the version displayed in GUI.")      

#        for b in [self.btn_start, self.btn_stop, self.btn_re, self.btn_reset, self.btn_stat, self.btn_upgrade, self.btn_stats, self.btn_deploy, self.btn_quit]:
        for b in [self.btn_start, self.btn_stop, self.btn_re, self.btn_reset, self.btn_stat, self.btn_upgrade, self.btn_stats, self.btn_deploy, self.btn_visualize, self.btn_report]:            
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
        self.btn_upgrade.clicked.connect(self.run_upgrade)
        
        self.update_timer_interval() # Initialize timer

    def open_report(self):
        if not hasattr(self, 'rep_window'):
            self.report_window = VisualizerReportWindow(self.server_data, self.console)
        self.report_window.show()
        # Trigger initial fetch for current day
#        self.viz_window.start_data_fetch()


    def open_visualizer(self):
        if not hasattr(self, 'viz_window'):
            self.viz_window = VisualizerWindow(self.server_data, self.console)
        self.viz_window.show()
        # Trigger initial fetch for current day
#        self.viz_window.start_data_fetch()

    def parse_to_bytes(self, s):
        if not s or "0 B" in s or "-" in s: return 0.0
        match = re.search(r'([\d\.]+)', s)
        if not match: return 0.0
        num = float(match.group(1))
        u = s.upper()
        if 'TB' in u: return num * 1024**4
        if 'GB' in u: return num * 1024**3
        if 'MB' in u: return num * 1024**2
        if 'KB' in u: return num * 1024
        return num

    def format_bytes(self, b):
        if b == 0: return "0 B"
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if b < 1024: return f"{b:.2f} {unit}"
            b /= 1024
        return f"{b:.2f} PB"

    def update_stats_table(self, results):
        """Updates the table using custom numeric items to preserve unit display."""
        self.stats_table.setSortingEnabled(False)
        
        win = self.edit_window.text()
        self.stats_table.setHorizontalHeaderLabels([
            "IP Address", "Avg Clients", f"Up ({win}m)", f"Down ({win}m)"
        ])
        self.stats_table.setRowCount(0)
        
        # Initial sort: Online first
        results.sort(key=lambda x: int(x['clients']) if x.get('success') and x['clients'].isdigit() else -1, reverse=True)
        
        COLOR_ONLINE = QColor("#27ae60")
        COLOR_OFFLINE = QColor("#c0392b")
        BG_OFFLINE = QColor("#fff5f5")
        COLOR_NO_DATA = QColor("#d68910")
        BG_NO_DATA = QColor("#fef9e7")
        
        total_clients = 0
        total_up_bytes = 0
        total_down_bytes = 0
        
        for r in results:
            row = self.stats_table.rowCount()
            self.stats_table.insertRow(row)
            
            is_ok = r.get("success", False)
            
            # Numeric values for math/sorting
            c_val = int(r["clients"]) if r["clients"].isdigit() else 0
            u_bytes = self.parse_to_bytes(r["up_val"])
            d_bytes = self.parse_to_bytes(r["down_val"])

            if is_ok:
                total_clients += c_val
                total_up_bytes += u_bytes
                total_down_bytes += d_bytes

            # 1. IP Item (Standard)
            ip_item = QTableWidgetItem(r["ip"])
            
            # 2. Client Item (Custom sort)
            client_text = str(c_val) if is_ok else r["clients"]
            client_item = NumericTableWidgetItem(client_text, c_val)

            # 3. Up Item (Custom sort - displays text, sorts by bytes)
            up_item = NumericTableWidgetItem(r["up_val"], u_bytes)

            # 4. Down Item (Custom sort - displays text, sorts by bytes)
            down_item = NumericTableWidgetItem(r["down_val"], d_bytes)

            items = [ip_item, client_item, up_item, down_item]
            
            for col, item in enumerate(items):
                item.setFlags(Qt.ItemIsSelectable | Qt.ItemIsEnabled)
                
                if is_ok:
                    if col == 0:
                        item.setForeground(QBrush(COLOR_ONLINE))
                        f = item.font(); f.setBold(True); item.setFont(f)
                else:
                    if r["clients"] == "Stopped":
                        item.setForeground(QBrush(COLOR_OFFLINE))
                        item.setBackground(QBrush(BG_OFFLINE))
                    else:
                        item.setForeground(QBrush(COLOR_NO_DATA))
                        item.setBackground(QBrush(BG_NO_DATA))

                    if col > 0 and r["clients"] != "Stopped":
                        item.setText("-")
                        # Set sort value to -1 so offline servers go to bottom in desc sort
                        if hasattr(item, 'sort_value'): item.sort_value = -1 
                
                if col != 0:
                    item.setTextAlignment(Qt.AlignCenter)
                
                self.stats_table.setItem(row, col, item)

        # Update Footer Labels
        self.lbl_total_clients.setText(f"Clients: {total_clients}")
        self.lbl_total_up.setText(f"Up: {self.format_bytes(total_up_bytes)}")
        self.lbl_total_down.setText(f"Down: {self.format_bytes(total_down_bytes)}")

        now = datetime.now().strftime("%H:%M:%S")
        self.lbl_last_updated.setText(f"Last Sync: {now}")

        self.stats_table.setSortingEnabled(True)


    def update_timer_interval(self):
        """Restarts the timer with the interval specified in the Refresh box."""
        try:
            val = self.edit_refresh.text().strip()
            if val:
                mins = float(val)
                if mins > 0:
                    # Restarts the countdown from 0
                    self.refresh_timer.start(int(mins * 60 * 1000))
        except ValueError:
            pass

    def run_auto_stats(self):
        """Forces an immediate refresh and resets the timer."""
        # Check if worker is already running to prevent overlapping
        if hasattr(self, 'auto_worker') and self.auto_worker.isRunning():
            return

        if not self.server_data:
            print("Debug: No server data found to refresh.")
            return

        # 1. Visual Feedback - This MUST happen first
        self.btn_refresh_now.setEnabled(False)
        self.btn_refresh_now.setText("...")
        
        # 2. Reset the timer interval
        self.update_timer_interval()

        # 3. Get parameters
        try:
            win_val = int(self.edit_window.text().strip())
            clamped = max(1, min(60, win_val))
            time_window_str = f"{clamped} minutes ago"
        except:
            time_window_str = "60 minutes ago"

        mode = 'name' if self.rad_name.isChecked() else 'ip'

        # 4. Initialize Worker
        # IMPORTANT: Assign to self.auto_worker so it isn't deleted by Python
        self.auto_worker = AutoStatsWorker(self.server_data, mode, time_window_str)
        
        # Connect signals
        self.auto_worker.stats_ready.connect(self.update_stats_table)
        self.auto_worker.finished.connect(self.on_worker_finished)
        
        # 5. Start
        print(f"Starting manual refresh for {len(self.server_data)} servers...")
        self.auto_worker.start()

    def on_worker_finished(self):
        """Restores the button state."""
        self.btn_refresh_now.setText("↻")
        self.btn_refresh_now.setEnabled(True)
        print("Debug: Refresh complete.")

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
        
        self.deploy_thread = DeployWorker("deploy",valid_targets, params)
        self.deploy_thread.log_signal.connect(lambda m: self.console.appendPlainText(m))
        self.deploy_thread.remove_password_signal.connect(self.remove_password_from_file)
        self.deploy_thread.finished.connect(lambda: self.btn_deploy.setEnabled(True))
        self.deploy_thread.finished.connect(lambda: self.btn_deploy.setText("Deploy"))
        
        self.deploy_thread.start()

    def get_target_servers(self, warnin_flag):
        """
        Returns a list of server IPs based on input or table selection.
        """

        selected_targets = [self.find_data_by_item(self.sel.item(i)) for i in range(self.sel.count())]
    
        if selected_targets:
            # Split by comma or space and clean up
            return selected_targets

        # 2. If panel is empty, get highlighted rows from the table
        selected_ips = []
    
        # We use selectedIndexes to identify unique rows
        indexes = self.stats_table.selectionModel().selectedRows()
    
        selected_targets = []
        for index in indexes:
            row = index.row()            
            ip_item = self.stats_table.item(row, 0) 
            if ip_item:
                for s in self.server_data:
                    if s['ip'] == ip_item.text().strip():
                        selected_targets.append(s)

        if selected_targets and warnin_flag:
            QMessageBox.warning(self, "Information", "You have selected servers from Status Tables")

        return selected_targets

    def run_upgrade(self):
        # 1. Get targets

        selected_targets = self.get_target_servers(True)

        validated = self.get_validated_inputs()
        if not validated: return 

        valid_targets = []

        # THE WARNING GATE ---
        target_names = ", ".join([s.get('name', s['ip']) for s in selected_targets])
        
        warning_msg = (
            "⚠️ CRITICAL: UPGARDE CONDUIT\n\n"
            f"You are about to upgrade: {target_names}\n\n"
            "This action will:\n"
            "• Connect as ROOT\n"
            "• UPGARDE the existing conduit applicatinon\n"
            "Are you sure you want to proceed?"
        )

        # Show the dialog with 'No' as the default safe choice
        reply = QMessageBox.warning(
            self, 
            "Confirm System Upgrade", 
            warning_msg,
            QMessageBox.Yes | QMessageBox.No, 
            QMessageBox.No
        )

        if reply != QMessageBox.Yes:
            self.console.appendPlainText("[CANCELLED] Upgrade aborted by user.")
            return

        # 4. Final Verification
        if not selected_targets: return

        params = {
            "user": "root",
            "clients": validated['clients'], 
            "bw": validated['bw']            
        }

        # UI Feedback and Start Thread
        self.btn_upgrade.setEnabled(False)
        self.btn_upgrade.setText("Upgrading...")
        
        self.deploy_thread = DeployWorker("upgrade",selected_targets, params)
        self.deploy_thread.log_signal.connect(lambda m: self.console.appendPlainText(m))
        self.deploy_thread.finished.connect(lambda: self.btn_upgrade.setEnabled(True))
        self.deploy_thread.finished.connect(lambda: self.btn_upgrade.setText("Upgrade"))
        
        self.deploy_thread.start()

    def run_stats(self):
        targets = self.get_target_servers(False)
        '''
        targets = [self.find_data_by_item(self.sel.item(i)) for i in range(self.sel.count())]
        if not targets: 
            QMessageBox.warning(self, "Stats", "Add servers to the right-side list first.")
            return
        '''    
        # Check which radio button is active
        mode = 'name' if self.rad_name.isChecked() else 'ip'
        
        self.console.appendPlainText(f"\n[>>>] Fetching Statistics (Display: {mode.upper()})...")
        self.stats_thread = StatsWorker(targets, mode)
        self.stats_thread.finished_signal.connect(lambda m: self.console.appendPlainText(m))
        self.stats_thread.start()

    def confirm_action(self, action):
        """Standard guard for Start, Stop, and Restart"""
#        count = self.sel.count()

        targets = self.get_target_servers(True)
        count = len(targets)
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
#        targets = [self.find_data_by_item(self.sel.item(i)) for i in range(self.sel.count())]
        
        targets = self.get_target_servers(True)
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
                            print(parts[0])
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
        '''
        targets = []
        for i in range(self.sel.count()):
            item = self.sel.item(i)
            server_dict = self.find_data_by_item(item)
            if server_dict:
                targets.append(server_dict)
        
        '''
        targets = self.get_target_servers(False)

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

class VisualizerWindow(QMainWindow):
    def __init__(self, server_list, console):
        super().__init__()
        self.setWindowTitle("Conduit Analytics Visualizer")
        self.resize(1400, 850)
        self.server_list = server_list
        self.server_list = sorted(self.server_list, key=lambda x: x['ip'])
        self.console = console
        
        self.allow_network = False # Flag to block any automatic network activity
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        main_layout = QVBoxLayout(main_widget)
        
        # Splitter allows user to resize the sidebar vs graph area
        splitter = QSplitter(Qt.Horizontal)
        self._is_initializing = True
        # --- LEFT PANEL: IP List ---
        self.ip_list = QListWidget()
        self.ip_list.setFixedWidth(180)
        # Populate IPs
        for s in self.server_list:
            self.ip_list.addItem(s['ip'])
        
        self.ip_list.setStyleSheet("""
            QListWidget {
                font-family: 'Consolas';
                font-size: 14px;
                background-color: #2b2b2b;
                color: #ffffff;
                border: 1px solid #555;
            }
            QListWidget::item {
                height: 30px; /* Increases the row height */
                padding-left: 10px;
            }
            QListWidget::item:selected {
                background-color: #4a90e2;
            }
        """)

        # CHANGE: Use currentItemChanged for Click/Arrow Key navigation
#        self.ip_list.currentItemChanged.connect(self.handle_selection_change)

        splitter.addWidget(self.ip_list)
        
        # --- RIGHT PANEL: Canvas with 3 Plots ---
        self.canvas = pg.GraphicsLayoutWidget()
        self.canvas.setBackground('k') # Black background often looks sharper for data
        
        # Setup 3 Vertical Plots with Date Axes
        self.p_clients = self.canvas.addPlot(row=0, col=0, axisItems={'bottom': DateAxisItem(orientation='bottom')})
        self.p_up = self.canvas.addPlot(row=1, col=0, axisItems={'bottom': DateAxisItem(orientation='bottom')})
        self.p_down = self.canvas.addPlot(row=2, col=0, axisItems={'bottom': DateAxisItem(orientation='bottom')})
        
        # Configure axes and titles
        plot_configs = [
            (self.p_clients, "Total Clients", "#00d2ff"),
            (self.p_up, "Upload Traffic (Bytes)", "#3aeb34"),
            (self.p_down, "Download Traffic (Bytes)", "#ff9f43")
        ]
        
        for plot, title, color in plot_configs:
            plot.setTitle(title, color=color, size="12pt")
            plot.showGrid(x=True, y=True, alpha=0.3)
            plot.getAxis('bottom').setLabel("Time (MM:DD HH:MM)")
            
        splitter.addWidget(self.canvas)
        main_layout.addWidget(splitter)
        
        # --- BOTTOM PANEL: Controls ---
        bottom_frame = QFrame()
        bottom_frame.setFixedHeight(50)
        bottom_lay = QHBoxLayout(bottom_frame)
        
        bottom_lay.addWidget(QLabel("Log Window (days):"))
        self.edit_days = QLineEdit("1")
        self.edit_days.setFixedWidth(60)
        bottom_lay.addWidget(self.edit_days)
        
       
        self.progress_bar = QProgressBar()
        self.progress_bar.setFixedWidth(300)
        self.progress_bar.setVisible(False)  # Hidden until "Reload" is clicked
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setAlignment(Qt.AlignCenter)
        bottom_lay.addWidget(self.progress_bar)
        

        self.btn_reload = QPushButton("Reload to retrieve the data")
        self.btn_reload.setFixedWidth(200)
        self.btn_reload.clicked.connect(self.start_data_fetch)
        bottom_lay.addWidget(self.btn_reload)
        
# --- PLOT MODE SELECTION (Radio Buttons) ---
#        mode_group_box = QGroupBox("Plot Mode")
#        mode_layout = QHBoxLayout()
        
        bottom_lay.addWidget(QLabel("Traffic Mode "))
        self.radio_total = QRadioButton("Total")
        self.radio_instant = QRadioButton("Interval")
        self.radio_instant.setChecked(True) # Default to your current delta view
        
        # Group them to ensure mutual exclusivity
        self.mode_group = QButtonGroup(self)
        self.mode_group.addButton(self.radio_total)
        self.mode_group.addButton(self.radio_instant)
        
        bottom_lay.addWidget(self.radio_total)
        bottom_lay.addWidget(self.radio_instant)

        self.radio_total.setChecked(True)

#        mode_group_box.setLayout(mode_layout)
        
        # Add to your existing bottom_lay
#        bottom_lay.addWidget(mode_group_box)

        self.radio_total.clicked.connect(self.refresh_current_plot)

        self.radio_instant.clicked.connect(self.refresh_current_plot)

        self.status_label = QLabel("Last Sync: Never")
        # Use Consolas for that "Conduit Version" terminal look
        self.status_label.setFont(QFont("Consolas", 10, QFont.Bold))
        self.set_status_color("red")


        bottom_lay.addStretch()
        bottom_lay.addWidget(self.status_label)

        main_layout.addWidget(bottom_frame)
        self.p_up.setXLink(self.p_clients)
        self.p_down.setXLink(self.p_clients)

        self.data_cache = {} # The central memory store

        self.load_all_logs_into_memory()
        self.console.appendPlainText(f"Importing data finished.")        
        self.ip_list.currentItemChanged.connect(self.refresh_current_plot)
        self.check_local_data_on_startup()        
        self._is_initializing = False     

    def set_status_color(self, color_name):
        """Sets the status label color (red for old, dark gray/white for fresh)."""
        color_map = {
            "red": "#ff4d4d",
            "dark": "#888888" # Professional dark gray for updated state
        }
        hex_color = color_map.get(color_name, "#ffffff")
        self.status_label.setStyleSheet(f"color: {hex_color};")

    def get_last_log_time(self, ip):
        """Reads the very last line of a local log file to get the timestamp."""
        file_path = f"server_logs/{ip}.log"
        if not os.path.exists(file_path):
            return None
        try:
            with open(file_path, 'rb') as f:
                f.seek(-2, os.SEEK_END)
                while f.read(1) != b'\n':
                    f.seek(-2, os.SEEK_CUR)
                last_line = f.readline().decode()
                return last_line.split('\t')[0] # Returns "YYYY-MM-DD HH:MM:SS"
        except Exception:
            return None

    def check_local_data_on_startup(self):
        """Ensures the first server is actually rendered on window open."""
        if self.ip_list.count() > 0:
            # 1. Highlight the first item
            self.ip_list.setCurrentRow(0)
            
            # 2. Force the window to 'calculate' its layout and sizes
            # This prevents the "blank graph" issue
            QApplication.processEvents() 

            # 3. Get the first IP and its cached data
            ip = self.ip_list.item(0).text()
            if ip in self.data_cache:
                data = self.data_cache[ip]
                
                # 4. Explicitly call the plot based on radio state
                if self.radio_total.isChecked():
                    self.plot_cumulative(data, ip)
                else:
                    self.plot_instantaneous(data)
                
                # 6. Force the axes to find the data points
                self.p_clients.enableAutoRange()
                self.p_up.enableAutoRange()
                self.p_down.enableAutoRange()

                # 5. Update the Sync Label for the first time
                if data['epochs']:
                    last_ts = datetime.fromtimestamp(data['epochs'][-1]).strftime("%Y-%m-%d %H:%M:%S")
                    self.status_label.setText(f"Last Sync: {last_ts}")
                    self.set_status_color("red")            

    def start_data_fetch(self):
        """User manually clicked 'Reload'. NOW we start the SSH download."""
        self.allow_network = True  # Enable network mode
        self.set_status_color("dark") # Change color to dark as requested
        
        days = self.edit_days.text()
        self.btn_reload.setEnabled(False)
#        self.progress_bar.setVisible(True)
#        self.progress_bar.setValue(0)
#        self.progress_bar.setFormat(f"Downloading")
        self.status_label.setText("Retrieving data started...")
        # This is where the actual 'Downloading' happens
        self.worker = HistoryWorker(self.server_list, days)
        self.worker.progress.connect(self.update_progress_ui)
        self.worker.all_finished.connect(self.on_fetch_complete)
        self.worker.start()

    def update_progress_ui(self, value):
        """Updates the bar and the text format."""
        self.progress_bar.setValue(value)
        self.progress_bar.setFormat(f"Downloading Logs: %p%")


    def parse_to_bytes(self, size_str):
        """Helper to convert '10.5 GB' to raw integer bytes."""
        units = {"B": 1, "KB": 1024, "MB": 1024*1024, "GB": 1024*1024*1024, "TB": 1024*1024*1024*1024}
        try:
            number, unit = size_str.split()
            return int(float(number) * units.get(unit.upper(), 1))
        except:
            return 0

    def process_raw_file(self, ip):
        """
        Takes the raw journalctl output and converts it to a clean tab-separated log.
        This runs on the local machine after all downloads are finished.
        """
        raw_path = f"server_logs/{ip}.raw"
        log_path = f"server_logs/{ip}.log"
    
        if not os.path.exists(raw_path):
            return

        # 1. Regex to extract: Date, Clients, UP, DOWN

        pattern = r"^(\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2})\s\[STATS\].*?Connected:\s*(\d+).*?Up:\s*([\d\.]+\s*\w+).*?Down:\s*([\d\.]+\s*\w+)"
    
        valid_lines = 0
        try:
            with open(raw_path, "r") as r, open(log_path, "w") as f:
                for line in r:
                    match = re.search(pattern, line)
                    if match:
                        dt_raw, clients, up_str, down_str = match.groups()
                    
                        # 2. Format data
                        dt = dt_raw.replace('T', ' ')
                        up_bytes = self.parse_to_bytes(up_str)
                        down_bytes = self.parse_to_bytes(down_str)                    
                        # 3. Write standardized columns
                        f.write(f"{dt}\t{clients}\t{up_bytes}\t{down_bytes}\n")
                        valid_lines += 1
        
            # Optional: Remove the raw file to save space after processing
            os.remove(raw_path)
            print(f"✅ {ip}: Processed {valid_lines} lines.")
        
        except Exception as e:
            print(f"❌ Error processing raw data for {ip}: {e}")

    def on_fetch_complete(self):
        """Called when HistoryWorker (the network threads) finishes."""
        self.status_label.setText("Processing Raw Logs...")

        # 1. Convert all RAW files to clean LOG files
        for server in self.server_list:
            self.process_raw_file(server['ip'])

        # 2. Load the newly cleaned data into the Memory Cache
        self.status_label.setText("Importing data...")
        self.load_all_logs_into_memory()
        self.console.appendPlainText(f"Importing data finished.")
        # 3. Refresh the GUI
        self.progress_bar.setVisible(False)
        self.btn_reload.setEnabled(True)
        if self.ip_list.currentItem():
            self.handle_selection_change(self.ip_list.currentItem(), None)
    
        self.status_label.setText("Sync Complete")

    def handle_selection_change(self, current, previous):
        """Switching is now instantaneous because it uses self.data_cache."""
        if not current: return
        ip = current.text()
        
        # Check if the IP exists in our memory cache
        if ip in self.data_cache:
            data_obj = self.data_cache[ip] # This is the dictionary
            
            # 1. Update Timestamp Label
            if data_obj['epochs']:
                last_ts = datetime.fromtimestamp(data_obj['epochs'][-1]).strftime("%Y-%m-%d %H:%M:%S")
                self.status_label.setText(f"Last Sync: {last_ts}")
                
                # Logic for color: Red if idle, Dark if reloading
                if not self.progress_bar.isVisible():
                    self.set_status_color("red")
                else:
                    self.set_status_color("dark")

            # 2. PASS THE DICTIONARY, NOT THE IP STRING
            if self.radio_total.isChecked():
                self.plot_cumulative(data_obj, ip)   # Pass the object {}
            else:
                self.plot_instantaneous(data_obj) # Pass the object {}
        else:
            self.status_label.setText("Last Sync: No Data in Cache")

    def refresh_current_plot(self):
        """One function to rule them all. Call this whenever any UI setting changes."""
        current_item = self.ip_list.currentItem()
        if not current_item:
            return
            
        ip = current_item.text()
        if ip in self.data_cache:
            data_obj = self.data_cache[ip]
            
            if self.radio_total.isChecked():
                self.plot_cumulative(data_obj, ip)
            else:
                self.plot_instantaneous(data_obj)

    def get_dynamic_scale(self, max_value):
        KB = 1024
        MB = 1024 ** 2
        GB = 1024 ** 3
        TB = 1024 ** 4

        if max_value < KB:
            return 1, "Bytes"
        elif max_value < MB:
            return KB, "KB"
        elif max_value < GB:
            return MB, "MB"
        elif max_value < TB:
            return GB, "GB"
        else:
            return TB, "TB"

    def plot_instantaneous(self, data):
        """Plots speed (deltas) using cached memory data."""

        # 1. Always clear first to ensure we don't overlay data
        self.p_clients.clear()
        self.p_up.clear()
        self.p_down.clear()

        epochs = data.get('epochs', [])
        
        # 2. Check for insufficient data
        if len(epochs) < 2:
            self.p_up.setTitle("Up (No Data)")
            self.p_down.setTitle("Down (No Data)")
            # Re-enable auto-range so it's ready for the next valid click
            for p in [self.p_clients, self.p_up, self.p_down]:
                p.enableAutoRange()
            return

        MB = 1024 * 1024
        unit = "MBps"
        diff_epochs = epochs[1:]
        diff_ups_mb = []
        diff_downs_mb = []

        for i in range(1, len(epochs)):
            time_delta = epochs[i] - epochs[i-1]
            up_delta = max(0, data['ups'][i] - data['ups'][i-1])
            down_delta = max(0, data['downs'][i] - data['downs'][i-1])
            
            # Speed = delta / time
            divisor = time_delta if time_delta > 0 else 1
            diff_ups_mb.append((up_delta / MB) / divisor)
            diff_downs_mb.append((down_delta / MB) / divisor)

        self.p_clients.plot(epochs, data['clients'], pen=pg.mkPen('#00d2ff', width=2), clear=True)
        self.p_up.plot(diff_epochs, diff_ups_mb, pen=pg.mkPen('#3aeb34', width=2), clear=True)
        self.p_down.plot(diff_epochs, diff_downs_mb, pen=pg.mkPen('#ff9f43', width=2), clear=True)
        
        self.p_up.setTitle(f"Up ({unit})")
        self.p_down.setTitle(f"Down ({unit})")

        # Rescale Y-axis for the new data
        for p in [self.p_clients, self.p_up, self.p_down]: p.enableAutoRange(axis='y')

    def plot_cumulative(self, data, ip):
        """Plots total usage using cached memory data with dynamic units."""
        # 1. Always clear first to ensure we don't overlay data
        self.p_clients.clear()
        self.p_up.clear()
        self.p_down.clear()

        epochs = data.get('epochs', [])
        
        # 2. Check for insufficient data
        if len(epochs) < 2:
            self.p_up.setTitle("Up (No Data)")
            self.p_down.setTitle("Down (No Data)")
            # Re-enable auto-range so it's ready for the next valid click
            for p in [self.p_clients, self.p_up, self.p_down]:
                p.enableAutoRange()
            return
        
        # 1. Determine the scale based on the highest value in either Up or Down
        max_up = data['ups'][-1] if data['ups'] else 0
        max_down = data['downs'][-1] if data['downs'] else 0
        max_val = max(max_up, max_down)

        # 2. Apply your specific rules
        KB = 1024
        MB = 1024 * 1024
        GB = 1024 * 1024 * 1024
        TB = 1024 * 1024 * 1024 * 1024

        if max_val >= KB and max_val < MB:
            divisor, unit = KB, "KBytes"
        elif max_val >= MB and max_val < GB:
            divisor, unit = MB, "MBytes"
        elif max_val >= GB and max_val < TB:
            divisor, unit = GB, "GBytes"
        elif max_val >= TB:
            divisor, unit = TB, "TBytes"
        else:
            divisor, unit = 1, "Bytes"

        # 3. Scale the data arrays
        scaled_ups = [x / divisor for x in data['ups']]
        scaled_downs = [x / divisor for x in data['downs']]

        # 4. Plot scaled data
        self.p_clients.plot(data['epochs'], data['clients'], pen=pg.mkPen('#00d2ff', width=2), clear=True)
        self.p_up.plot(data['epochs'], scaled_ups, pen=pg.mkPen('#3aeb34', width=2), clear=True)
        self.p_down.plot(data['epochs'], scaled_downs, pen=pg.mkPen('#ff9f43', width=2), clear=True)

        # 5. Update Titles/Labels to show the unit
        if ip != "---.---.---.---":
            self.p_clients.setTitle(f"Total Clients")
            self.p_up.setTitle(f"Total Up ({unit})")            
            self.p_down.setTitle(f"Total Down ({unit})")
        else:
            self.p_up.setTitle(f"Total Up - all servers ({unit})")
            self.p_down.setTitle(f"Total Down - all servers ({unit})")
            self.p_clients.setTitle(f"Total Clients - all servers")

        for p in [self.p_clients, self.p_up, self.p_down]: 
            p.enableAutoRange(axis='y')      

    def load_all_logs_into_memory(self):
        """Reads logs and creates a Global Total with reboot-resilient summing."""

        existing_items = self.ip_list.findItems("---.---.---.---", Qt.MatchExactly)

        # If it exists, remove it
        if existing_items:
            for item in existing_items:
                row = self.ip_list.row(item)
                self.ip_list.takeItem(row)

        self.data_cache.clear()
        server_list = sorted(self.server_list, key=lambda x: x['ip'])
        
        all_epochs = []
        for server in server_list:
            ip = server['ip']
            file_path = f"server_logs/{ip}.log"
            if os.path.exists(file_path):
                print(f"Reading: {ip}")
                data = self.parse_log_file(file_path)
                self.data_cache[ip] = data
                if data['epochs']:
                    all_epochs.extend([data['epochs'][0], data['epochs'][-1]])

        if not all_epochs:
            return

        # --- SETUP FOR GLOBAL SUMMING ---
        start_t = int(min(all_epochs))
        end_t = int(max(all_epochs))
        
        server_ips = list(self.data_cache.keys())
        cursors = {ip: 0 for ip in server_ips}
        
        # Track offsets specifically for the Global Total calculation
        # This prevents 'reboot drops' from affecting the 255.255.255.255 data.
        up_offsets = {ip: 0 for ip in server_ips}
        down_offsets = {ip: 0 for ip in server_ips}
        
        total_epochs, total_clients, total_ups, total_downs = [], [], [], []

        # 3. Resample: Iterate every second
        for current_t in range(start_t, end_t + 1):
            s_clients = 0
            s_ups = 0
            s_downs = 0

            for ip in server_ips:
                data = self.data_cache[ip]
                idx = cursors[ip]
                
                # Check for counter reset BEFORE moving to the next point. This happen when a server restart.
                if idx + 1 < len(data['epochs']) and data['epochs'][idx + 1] <= current_t:
                    # Look ahead: if next value is lower than current, it's a reboot
                    if data['ups'][idx + 1] < data['ups'][idx]:
                        up_offsets[ip] += data['ups'][idx]
                        print(f"📈 [Totalizer] Up-Reset detected on {ip} at {current_t}")
                    
                    if data['downs'][idx + 1] < data['downs'][idx]:
                        down_offsets[ip] += data['downs'][idx]
                        print(f"📈 [Totalizer] Down-Reset detected on {ip} at {current_t}")

                    # Now safely move the cursor forward
                    while idx + 1 < len(data['epochs']) and data['epochs'][idx + 1] <= current_t:
                        idx += 1
                    cursors[ip] = idx
                
                # Sum the value + any accumulated offsets for this server
                s_clients += data['clients'][idx]
                s_ups     += (data['ups'][idx] + up_offsets[ip])
                s_downs   += (data['downs'][idx] + down_offsets[ip])

            total_epochs.append(float(current_t))
            total_clients.append(s_clients)
            total_ups.append(s_ups)
            total_downs.append(s_downs)

        # 5. Assign to virtual IP
        self.data_cache["---.---.---.---"] = {
            'epochs': total_epochs, 'clients': total_clients,
            'ups': total_ups, 'downs': total_downs
        }
        self.ip_list.addItem("---.---.---.---")


    def decimate_by_download(self, raw_rows):
        """
        Groups data by constant Download values. 
        Averages clients and upload during the stagnant period.
        """
        if not raw_rows:
            return []

        decimated = []
        
        # State trackers for the current "bucket"
        current_batch_clients = []
        current_batch_ups = []
        
        # Initialize with the first row
        # row: [timestamp_str, clients, ups, downs]
        first_ts = datetime.strptime(raw_rows[0][0], "%Y-%m-%d %H:%M:%S")
        anchor_down = int(raw_rows[0][3])
        
        current_batch_clients.append(int(raw_rows[0][1]))
        current_batch_ups.append(int(raw_rows[0][2]))
        
        last_ts = first_ts

        for i in range(1, len(raw_rows)):
            ts = datetime.strptime(raw_rows[i][0], "%Y-%m-%d %H:%M:%S")
            clients = int(raw_rows[i][1])
            ups = int(raw_rows[i][2])
            downs = int(raw_rows[i][3])

            if downs == anchor_down:
                # Still the same download value, keep accumulating for the average
                current_batch_clients.append(clients)
                current_batch_ups.append(ups)
                last_ts = ts
            else:
                # Download changed! Commit the averaged results for the previous window
                avg_clients = round(sum(current_batch_clients) / len(current_batch_clients))
                avg_ups = int(sum(current_batch_ups) / len(current_batch_ups))
                
                # We use the 'last_ts' to show the state just before the download incremented
                decimated.append((last_ts, avg_clients, avg_ups, anchor_down))
                
                # Reset for the new anchor
                anchor_down = downs
                current_batch_clients = [clients]
                current_batch_ups = [ups]
                last_ts = ts

        # Don't forget to add the final bucket
        if current_batch_clients:
            avg_clients = round(sum(current_batch_clients) / len(current_batch_clients))
            avg_ups = int(sum(current_batch_ups) / len(current_batch_ups))
            decimated.append((last_ts, avg_clients, avg_ups, anchor_down))

        return decimated

    def parse_log_file(self, file_path):
        """Converts raw disk text into high-speed memory arrays with decimation."""
        raw_rows = []
        try:
            with open(file_path, 'r') as f:
                for line in f:
                    parts = line.strip().split('\t')
                    if len(parts) == 4:
                        # parts: [timestamp_str, clients, ups, downs]
                        raw_rows.append(parts)
            
            # Apply decimation before converting to final dictionary
            clean_rows = self.decimate_by_download(raw_rows)
            
            # Convert decimated rows into the final cache format
            data = {'epochs': [], 'clients': [], 'ups': [], 'downs': []}
            for row in clean_rows:
                # row is (datetime_obj, avg_clients, avg_ups, anchor_down)
                data['epochs'].append(row[0].timestamp())
                data['clients'].append(row[1])
                data['ups'].append(row[2])
                data['downs'].append(row[3])
                
            return data

        except Exception as e:
            print(f"Error parsing {file_path}: {e}")
            return {'epochs': [], 'clients': [], 'ups': [], 'downs': []}

class VisualizerReportWindow(QMainWindow):
    def __init__(self, server_list, console):
        super().__init__()
        self.setWindowTitle("Conduit Analytics Report")
        self.resize(1400, 850)
        self.server_list = server_list
        self.server_list = sorted(self.server_list, key=lambda x: x['ip'])
        self.console = console
        
        self.allow_network = False # Flag to block any automatic network activity
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        main_layout = QVBoxLayout(main_widget)
        
        # Splitter allows user to resize the sidebar vs graph area
        splitter = QSplitter(Qt.Horizontal)
        self._is_initializing = True
        # --- LEFT PANEL: IP List ---
        self.ip_list = QListWidget()
        self.ip_list.setFixedWidth(180)
        # Populate IPs
        for s in self.server_list:
            self.ip_list.addItem(s['ip'])
        
        self.ip_list.setStyleSheet("""
            QListWidget {
                font-family: 'Consolas';
                font-size: 14px;
                background-color: #2b2b2b;
                color: #ffffff;
                border: 1px solid #555;
            }
            QListWidget::item {
                height: 30px; /* Increases the row height */
                padding-left: 10px;
            }
            QListWidget::item:selected {
                background-color: #4a90e2;
            }
        """)

        # CHANGE: Use currentItemChanged for Click/Arrow Key navigation
#        self.ip_list.currentItemChanged.connect(self.handle_selection_change)

        splitter.addWidget(self.ip_list)
        
        # --- RIGHT PANEL: Canvas with 3 Plots ---
        self.canvas = pg.GraphicsLayoutWidget()
        self.canvas.setBackground('k') # Black background often looks sharper for data
        
        # Setup 3 Vertical Plots with Date Axes
        self.p_clients = self.canvas.addPlot(row=0, col=0, axisItems={'bottom': DateAxisItem(orientation='bottom')})
        self.p_up = self.canvas.addPlot(row=1, col=0, axisItems={'bottom': DateAxisItem(orientation='bottom')})
        self.p_down = self.canvas.addPlot(row=2, col=0, axisItems={'bottom': DateAxisItem(orientation='bottom')})
        
        # Configure axes and titles
        plot_configs = [
            (self.p_clients, "Total Clients", "#00d2ff"),
            (self.p_up, "Upload Traffic (Bytes)", "#3aeb34"),
            (self.p_down, "Download Traffic (Bytes)", "#ff9f43")
        ]
        
        for plot, title, color in plot_configs:
            plot.setTitle(title, color=color, size="12pt")
            plot.showGrid(x=True, y=True, alpha=0.3)
            plot.getAxis('bottom').setLabel("Time (MM:DD HH:MM)")
            
        splitter.addWidget(self.canvas)
        main_layout.addWidget(splitter)
        
        # --- BOTTOM PANEL: Controls ---
        bottom_frame = QFrame()
        bottom_frame.setFixedHeight(50)
        bottom_lay = QHBoxLayout(bottom_frame)
                       
        self.progress_bar = QProgressBar()
        self.progress_bar.setFixedWidth(300)
        self.progress_bar.setVisible(False)  # Hidden until "Reload" is clicked
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setAlignment(Qt.AlignCenter)
        bottom_lay.addWidget(self.progress_bar)
        

        self.btn_reload = QPushButton("Reload to retrieve the data")
        self.btn_reload.setFixedWidth(200)
        self.btn_reload.clicked.connect(self.start_data_fetch)
        bottom_lay.addWidget(self.btn_reload)
        

#        self.radio_total.clicked.connect(self.refresh_current_plot)

#        self.radio_instant.clicked.connect(self.refresh_current_plot)

        self.lbl_total_clients = QLabel("Clients: 0")
        self.lbl_total_up = QLabel("Up: 0 B")
        self.lbl_total_down = QLabel("Down: 0 B")

        for lbl in [self.lbl_total_clients, self.lbl_total_up, self.lbl_total_down]:
            lbl.setStyleSheet("font-weight: bold; color: #2c3e50;")
            lbl.setFixedWidth(180)
            bottom_lay.addWidget(lbl)

        self.status_label = QLabel("Last Sync: Never")
        # Use Consolas for that "Conduit Version" terminal look
        self.status_label.setFont(QFont("Consolas", 10, QFont.Bold))
        self.set_status_color("red")


        bottom_lay.addStretch()
        bottom_lay.addWidget(self.status_label)

        main_layout.addWidget(bottom_frame)
        self.p_up.setXLink(self.p_clients)
        self.p_down.setXLink(self.p_clients)

        self.data_cache = {} # The central memory store

        self.load_all_logs_into_memory()
        self.console.appendPlainText(f"Importing data finished.")        
        self.ip_list.currentItemChanged.connect(self.refresh_current_plot)
        self.check_local_data_on_startup()        
        self._is_initializing = False     

    def set_status_color(self, color_name):
        """Sets the status label color (red for old, dark gray/white for fresh)."""
        color_map = {
            "red": "#ff4d4d",
            "dark": "#888888" # Professional dark gray for updated state
        }
        hex_color = color_map.get(color_name, "#ffffff")
        self.status_label.setStyleSheet(f"color: {hex_color};")

    def get_last_log_time(self, ip):
        """Reads the very last line of a local log file to get the timestamp."""
        file_path = f"server_report_logs/{ip}.log"
        if not os.path.exists(file_path):
            return None
        try:
            with open(file_path, 'rb') as f:
                f.seek(-2, os.SEEK_END)
                while f.read(1) != b'\n':
                    f.seek(-2, os.SEEK_CUR)
                last_line = f.readline().decode()
                return last_line.split('\t')[0] # Returns "YYYY-MM-DD HH:MM:SS"
        except Exception:
            return None

    def check_local_data_on_startup(self):
        """Ensures the first server is actually rendered on window open."""
        if self.ip_list.count() > 0:
            # 1. Highlight the first item
            self.ip_list.setCurrentRow(0)
            
            # 2. Force the window to 'calculate' its layout and sizes
            # This prevents the "blank graph" issue
            QApplication.processEvents() 

            # 3. Get the first IP and its cached data
            ip = self.ip_list.item(0).text()
            if ip in self.data_cache:
                data = self.data_cache[ip]
                
                # 4. Explicitly call the plot based on radio state

                self.plot_report_interval(data, ip)
                
                # 6. Force the axes to find the data points
                self.p_clients.enableAutoRange()
                self.p_up.enableAutoRange()
                self.p_down.enableAutoRange()

                # 5. Update the Sync Label for the first time
                if data['epochs']:
                    last_ts = datetime.fromtimestamp(data['epochs'][-1]).strftime("%Y-%m-%d %H:%M:%S")
                    self.status_label.setText(f"Last Sync: {last_ts}")
                    self.set_status_color("red")            

    def start_data_fetch(self):
        """User manually clicked 'Reload'. NOW we start the SSH download."""
        self.allow_network = True  # Enable network mode
        self.set_status_color("dark") # Change color to dark as requested
        
        self.btn_reload.setEnabled(False)
#        self.progress_bar.setVisible(True)
#        self.progress_bar.setValue(0)
#        self.progress_bar.setFormat(f"Downloading")
        self.status_label.setText("Retrieving data started...")
        # This is where the actual 'Downloading' happens
        self.worker = ReportWorker(self.server_list)
        self.worker.progress.connect(self.update_progress_ui)
        self.worker.all_finished.connect(self.on_fetch_complete)
        self.worker.start()

    def update_progress_ui(self, value):
        """Updates the bar and the text format."""
        self.progress_bar.setValue(value)
        self.progress_bar.setFormat(f"Downloading Logs: %p%")


    def parse_to_bytes(self, size_str):
        """Helper to convert '10.5 GB' to raw integer bytes."""
        units = {"B": 1, "KB": 1024, "MB": 1024*1024, "GB": 1024*1024*1024, "TB": 1024*1024*1024*1024}
        try:
            number, unit = size_str.split()
            return int(float(number) * units.get(unit.upper(), 1))
        except:
            return 0

    def process_raw_file(self, ip):
        """
        Takes the raw journalctl output and converts it to a clean tab-separated log.
        This runs on the local machine after all downloads are finished.
        """
        raw_path = f"server_report_logs/{ip}.raw"
        log_path = f"server_report_logs/{ip}.log"
    
        if not os.path.exists(raw_path):
            return

        # 1. Regex to extract: Date, Clients, UP, DOWN

        pattern = r"^(\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2}),\s*(\d+),\s*(\d+),\s*(\d+)"
    
        valid_lines = 0
        try:
            with open(raw_path, "r") as r, open(log_path, "w") as f:
                for line in r:
                    match = re.search(pattern, line)
                    if match:
                        dt_raw, clients, up_str, down_str = match.groups()
                    
                        # 2. Format data
                        dt = dt_raw.replace('T', ' ')
#                        up_bytes = self.parse_to_bytes(up_str)
#                        down_bytes = self.parse_to_bytes(down_str)
                        up_bytes = int(up_str)
                        down_bytes = int(down_str)
                    
                        # 3. Write standardized columns
                        f.write(f"{dt}\t{clients}\t{up_bytes}\t{down_bytes}\n")
                        valid_lines += 1
        
            # Optional: Remove the raw file to save space after processing
            os.remove(raw_path)
            print(f"✅ {ip}: Processed {valid_lines} lines.")
        
        except Exception as e:
            print(f"❌ Error processing raw data for {ip}: {e}")

    def on_fetch_complete(self):
        """Called when ReportWorker (the network threads) finishes."""
        self.status_label.setText("Processing Raw Logs...")

        # 1. Convert all RAW files to clean LOG files
        for server in self.server_list:
            self.process_raw_file(server['ip'])

        # 2. Load the newly cleaned data into the Memory Cache
        self.status_label.setText("Importing data...")
        self.load_all_logs_into_memory()
        self.console.appendPlainText(f"Importing data finished.")
        # 3. Refresh the GUI
        self.progress_bar.setVisible(False)
        self.btn_reload.setEnabled(True)
        if self.ip_list.currentItem():
            self.handle_selection_change(self.ip_list.currentItem(), None)
    
        self.status_label.setText("Sync Complete")

    def handle_selection_change(self, current, previous):
        """Switching is now instantaneous because it uses self.data_cache."""
        if not current: return
        ip = current.text()
        
        # Check if the IP exists in our memory cache
        if ip in self.data_cache:
            data_obj = self.data_cache[ip] # This is the dictionary
            
            # 1. Update Timestamp Label
            if data_obj['epochs']:
                last_ts = datetime.fromtimestamp(data_obj['epochs'][-1]).strftime("%Y-%m-%d %H:%M:%S")
                self.status_label.setText(f"Last Sync: {last_ts}")
                
                # Logic for color: Red if idle, Dark if reloading
                if not self.progress_bar.isVisible():
                    self.set_status_color("red")
                else:
                    self.set_status_color("dark")

            # 2. PASS THE DICTIONARY, NOT THE IP STRING

            self.plot_report_interval(data_obj, ip)   # Pass the object {}

        else:
            self.status_label.setText("Last Sync: No Data in Cache")

    def refresh_current_plot(self):
        """One function to rule them all. Call this whenever any UI setting changes."""
        current_item = self.ip_list.currentItem()
        if not current_item:
            return
            
        ip = current_item.text()
        if ip in self.data_cache:
            data_obj = self.data_cache[ip]
                        
            self.plot_report_interval(data_obj, ip)

    def get_dynamic_scale(self, max_value):
        KB = 1024
        MB = 1024 ** 2
        GB = 1024 ** 3
        TB = 1024 ** 4

        if max_value < KB:
            return 1, "Bytes"
        elif max_value < MB:
            return KB, "KB"
        elif max_value < GB:
            return MB, "MB"
        elif max_value < TB:
            return GB, "GB"
        else:
            return TB, "TB"

    def get_scale_unit(self, max_val):
        KB = 1024
        MB = 1024 ** 2
        GB = 1024 ** 3
        TB = 1024 ** 4

        if max_val >= KB and max_val < MB:
            divisor, unit = KB, "KBytes"
        elif max_val >= MB and max_val < GB:
            divisor, unit = MB, "MBytes"
        elif max_val >= GB and max_val < TB:
            divisor, unit = GB, "GBytes"
        elif max_val >= TB:
            divisor, unit = TB, "TBytes"
        else:
            divisor, unit = 1, "Bytes"
        return divisor, unit

    def plot_report_interval(self, data, ip):
        """Plots total usage using cached memory data with dynamic units."""
        # 1. Always clear first to ensure we don't overlay data
        self.p_clients.clear()
        self.p_up.clear()
        self.p_down.clear()

        epochs = data.get('epochs', [])
        
        # 2. Check for insufficient data
        if len(epochs) < 2:
            self.p_up.setTitle("Up (No Data)")
            self.p_down.setTitle("Down (No Data)")
            # Re-enable auto-range so it's ready for the next valid click
            for p in [self.p_clients, self.p_up, self.p_down]:
                p.enableAutoRange()
            return
        
        # 1. Determine the scale based on the highest value in either Up or Down
        max_up = max(data['ups']) if data['ups'] else 0
        max_down = max(data['downs']) if data['downs'] else 0
        max_val = max(max_up, max_down)
        
        # 2. Apply your specific rules
        KB = 1024
        MB = 1024 * 1024
        GB = 1024 * 1024 * 1024
        TB = 1024 * 1024 * 1024 * 1024

        divisor, unit = self.get_scale_unit(max_val)
        '''
        if max_val >= KB and max_val < MB:
            divisor, unit = KB, "KBytes"
        elif max_val >= MB and max_val < GB:
            divisor, unit = MB, "MBytes"
        elif max_val >= GB and max_val < TB:
            divisor, unit = GB, "GBytes"
        elif max_val >= TB:
            divisor, unit = TB, "TBytes"
        else:
            divisor, unit = 1, "Bytes"
        '''

        max_clients = max(data['clients'])
        total_up_bytes = sum(data['ups'])
        total_down_bytes = sum(data['downs'])

        # 3. Scale the data arrays
        scaled_ups = [x / divisor for x in data['ups']]
        scaled_downs = [x / divisor for x in data['downs']]

        # 4. Plot scaled data
        self.p_clients.plot(data['epochs'], data['clients'], pen=pg.mkPen('#00d2ff', width=2), clear=True)
        self.p_up.plot(data['epochs'], scaled_ups, pen=pg.mkPen('#3aeb34', width=2), clear=True)
        self.p_down.plot(data['epochs'], scaled_downs, pen=pg.mkPen('#ff9f43', width=2), clear=True)

        # 5. Update Titles/Labels to show the unit
        if ip != "---.---.---.---":
            self.p_clients.setTitle(f"Total Clients")
            self.p_up.setTitle(f"Total Up ({unit})")            
            self.p_down.setTitle(f"Total Down ({unit})")
        else:
            self.p_up.setTitle(f"Total Up - all servers ({unit})")
            self.p_down.setTitle(f"Total Down - all servers ({unit})")
            self.p_clients.setTitle(f"Total Clients - all servers")

        for p in [self.p_clients, self.p_up, self.p_down]: 
            p.enableAutoRange(axis='y')      

        divisor_up, unit_up = self.get_scale_unit(total_up_bytes,)
        divisor_down, unit_down = self.get_scale_unit(total_down_bytes)

        self.lbl_total_clients.setText(f"Max Clients: {max_clients}")
        self.lbl_total_up.setText(f"Total Up: {total_up_bytes/divisor_up:.1f} {unit_up}")
        self.lbl_total_down.setText(f"Total Down: {total_down_bytes/divisor_down:.1f} {unit_down}") 

    def load_all_logs_into_memory(self):

        """Reads logs and creates a Global Total with reboot-resilient summing."""

        existing_items = self.ip_list.findItems("---.---.---.---", Qt.MatchExactly)

        # If it exists, remove it
        if existing_items:
            for item in existing_items:
                row = self.ip_list.row(item)
                self.ip_list.takeItem(row)

        self.data_cache.clear()
        server_list = sorted(self.server_list, key=lambda x: x['ip'])
        
        all_epochs = []
        for server in server_list:
            ip = server['ip']
            file_path = f"server_report_logs/{ip}.log"
            if os.path.exists(file_path):
                print(f"Reading: {ip}")
                data = self.parse_log_file(file_path)
                self.data_cache[ip] = data
                if data['epochs']:
                    all_epochs.extend([data['epochs'][0], data['epochs'][-1]])
#        return

        if not all_epochs:
            return

        # --- SETUP FOR GLOBAL SUMMING ---
        start_t = int(min(all_epochs))
        end_t = int(max(all_epochs))
        
        server_ips = list(self.data_cache.keys())
        cursors = {ip: 0 for ip in server_ips}
        
        # Track offsets specifically for the Global Total calculation
        # This prevents 'reboot drops' from affecting the 255.255.255.255 data.
        up_offsets = {ip: 0 for ip in server_ips}
        down_offsets = {ip: 0 for ip in server_ips}
        
        total_epochs, total_clients, total_ups, total_downs = [], [], [], []

        # 3. Resample: Iterate every second
        for current_t in range(start_t, end_t + 1, 3600):
            s_clients = 0
            s_ups = 0
            s_downs = 0

            for ip in server_ips:
                data = self.data_cache[ip]
                if not data['clients']:
                    continue

                idx = cursors[ip]
                
                # Check for counter reset BEFORE moving to the next point. This happen when a server restart.
                if idx + 1 < len(data['epochs']) and data['epochs'][idx + 1] <= current_t:
                    # Look ahead: if next value is lower than current, it's a reboot
                    #if data['ups'][idx + 1] < data['ups'][idx]:
#                    up_offsets[ip] += data['ups'][idx]
                    #    print(f"📈 [Totalizer] Up-Reset detected on {ip} at {current_t}")
                    
                    #if data['downs'][idx + 1] < data['downs'][idx]:
#                    down_offsets[ip] += data['downs'][idx]
                    #    print(f"📈 [Totalizer] Down-Reset detected on {ip} at {current_t}")


                    # Now safely move the cursor forward
                    while idx + 1 < len(data['epochs']) and data['epochs'][idx + 1] <= current_t:
                        idx += 1
                    cursors[ip] = idx
                
                # Sum the value + any accumulated offsets for this server

                s_clients += data['clients'][idx]
                # s_ups     += (data['ups'][idx] + up_offsets[ip])
                s_ups     += data['ups'][idx]
                # s_downs   += (data['downs'][idx] + down_offsets[ip])
                s_downs   += data['downs'][idx]

            total_epochs.append(float(current_t))
            total_clients.append(s_clients)
            total_ups.append(s_ups)
            total_downs.append(s_downs)

        # 5. Assign to virtual IP
        self.data_cache["---.---.---.---"] = {
            'epochs': total_epochs, 'clients': total_clients,
            'ups': total_ups, 'downs': total_downs
        }
        self.ip_list.addItem("---.---.---.---")


    def parse_log_file(self, file_path):
        """Converts raw disk text into high-speed memory arrays with decimation."""
        raw_rows = []
        try:
            with open(file_path, 'r') as f:
                for line in f:
                    parts = line.strip().split('\t')
                    if len(parts) == 4:
                        # parts: [timestamp_str, clients, ups, downs]
                        raw_rows.append(parts)                            
            
            # Convert decimated rows into the final cache format
            data = {'epochs': [], 'clients': [], 'ups': [], 'downs': []}
            for row in raw_rows:
                # row is (datetime_obj, avg_clients, avg_ups, anchor_down)
                last_ts = datetime.strptime(row[0], "%Y-%m-%d %H:%M:%S")
                data['epochs'].append(last_ts.timestamp())
                data['clients'].append(int(row[1]))
                data['ups'].append(int(row[2]))
                data['downs'].append(int(row[3]))
                
            return data

        except Exception as e:
            print(f"Error parsing {file_path}: {e}")
            return {'epochs': [], 'clients': [], 'ups': [], 'downs': []}


if __name__ == "__main__":
    app = QApplication(sys.argv); gui = ConduitGUI(); gui.show(); sys.exit(app.exec_())