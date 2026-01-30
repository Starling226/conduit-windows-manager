import sys
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QHBoxLayout, QPushButton, QLabel, QLineEdit, 
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
                os.path.join(home, ".ssh", "id_rsa"),
                os.path.join(home, ".ssh", "id_ed25519"),
                os.path.join(home, ".ssh", "id_dsa"),
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

                if self.action == "status":
                    res = run_cmd("systemctl is-active conduit")
                    state = "Active" if res.ok else "Inactive"
                    return f"[*] {s['name']} ({s['ip']}): {state}"

                # ... (rest of the start/stop/restart logic using run_cmd)
                
        except Exception as e:
            return f"[!] {s['name']} Error: {str(e)}"            

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
        cfg_lay.addWidget(QLabel("Max Clients:")); self.in_clients = QLineEdit("225")
        cfg_lay.addWidget(self.in_clients)
        cfg_lay.addWidget(QLabel("Max Bandwidth:")); self.in_bw = QLineEdit("40.0")
        cfg_lay.addWidget(self.in_bw)
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
        self.btn_stat = QPushButton("Status"); self.btn_quit = QPushButton("Quit")
        self.btn_reset.setToolTip("Use if clients not added after hours or server waiting to connect.")
        for b in [self.btn_start, self.btn_stop, self.btn_re, self.btn_reset, self.btn_stat, self.btn_quit]:
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
        self.btn_re.clicked.connect(lambda: QMessageBox.information(self, "Info", "Use Restart if server is already running."))
        self.btn_start.clicked.connect(lambda: self.run_worker("start"))
        self.btn_stop.clicked.connect(lambda: self.run_worker("stop"))
        self.btn_stat.clicked.connect(lambda: self.run_worker("status"))

    # --- Robust Logic Methods ---

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
        self.console.appendPlainText(f"\n[DEBUG] Target IPs: {', '.join([t['ip'] for t in targets])}")
        
        conf = {
            "clients": self.in_clients.text(), 
            "bw": self.in_bw.text(), 
            "update": self.chk_upd.isChecked()
        }
        
        self.console.appendPlainText(f"[>>>] {action.upper()} on {len(targets)} servers...")
        self.worker = ServerWorker(action, targets, conf)
        self.worker.log_signal.connect(lambda m: self.console.appendPlainText(m))
        self.worker.start()

if __name__ == "__main__":
    app = QApplication(sys.argv); gui = ConduitGUI(); gui.show(); sys.exit(app.exec_())