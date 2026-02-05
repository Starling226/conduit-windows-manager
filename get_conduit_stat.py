#!/usr/bin/python3
import os
from datetime import datetime
import subprocess
import re

def parse_to_bytes(size_str):
    """Helper to convert '10.5 GB' to raw integer bytes."""
    units = {"B": 1, "KB": 1024, "MB": 1024**2, "GB": 1024**3, "TB": 1024**4}
    try:
        parts = size_str.split()
        if len(parts) < 2: return 0
        number, unit = parts[0], parts[1]
        return int(float(number) * units.get(unit.upper(), 1))
    except Exception:
        return 0

def format_bytes(b):
    if b == 0: return "0 B"
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if b < 1024: return f"{b:.2f} {unit}"
        b /= 1024
    return f"{b:.2f} PB"

def get_status(days=1):
    res = {"success": False, "time": "-", "clients": "0", "up_val": "0 B", "down_val": "0 B"}

    # Check if service is active
    status_check = subprocess.run(["systemctl", "is-active", "conduit.service"], 
                                  capture_output=True, text=True)
    
    if status_check.stdout.strip() != "active":
        res["clients"] = "No Data"
        return res

    # Command construction
    cmd = (
        f"journalctl -u conduit.service --since  '1 hour ago' --no-pager -o short-iso | "
        f"grep '[STATS]' | "
        f"sed 's/.*conduit\\[[0-9]*\\]: //'"
    )

    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, check=True)
        output = result.stdout.strip()
    except subprocess.CalledProcessError:
        res["clients"] = "No Data"
        return res

    if output:
        lines = output.splitlines()
        # Adjusted regex to be more flexible with whitespace
        pattern = r"(\d{4}-\d{2}-\d{2}.\d{2}:\d{2}:\d{2}).*?Connected:\s*(\d+).*?Up:\s*([\d\.]+\s*\w+).*?Down:\s*([\d\.]+\s*\w+)"
        
        data_points = []
        for line in lines:
            match = re.search(pattern, line)            
            if match:
                dt_raw, clients, up_str, down_str = match.groups()
                data_points.append({
                    't': dt_raw.replace('T', ' '),
                    'c': int(clients),
                    'u': parse_to_bytes(up_str),
                    'd': parse_to_bytes(down_str)
                })

        if data_points:
            res["success"] = True
            client_counts = [d['c'] for d in data_points]
            avg_clients = sum(client_counts) / len(client_counts)
            
            first, last = data_points[0], data_points[-1]

            res["time"] = last['t']
            res["clients"] = str(int(round(avg_clients)))
            # Delta between first and last log entry
            res["up_val"] = format_bytes(max(0, last['u'] - first['u']))
            res["down_val"] = format_bytes(max(0, last['d'] - first['d']))

    return res


def get_stat():
    results = get_status()
    
    # 1. Get current system year
    current_year = datetime.now().year
    filename = f"/opt/conduit/{current_year}-conduit.log"
    
    total_clients = 0
    total_up_bytes = 0
    total_down_bytes = 0
            
    is_ok = results.get("success", False)
    dt = results.get("time", "-")
    
    clients_raw = str(results.get("clients", "0"))
    c_val = int(clients_raw) if clients_raw.isdigit() else 0
    
    u_bytes = parse_to_bytes(results.get("up_val", "0 B"))
    d_bytes = parse_to_bytes(results.get("down_val", "0 B"))

    if is_ok:
        total_clients += c_val
        total_up_bytes += u_bytes
        total_down_bytes += d_bytes

        # 2. Log to the yearly file
        try:
            # Mode "a" handles "create if not exists" automatically
            with open(filename, "a") as f:
                log_row = f"{dt}, {total_clients}, {total_up_bytes}, {total_down_bytes}\n"
                f.write(log_row)
            print(f"Logged to {filename}: {log_row.strip()}")
        except IOError as e:
            print(f"Failed to write to {filename}: {e}")
    else:
        print("Service data unavailable; skipping log entry.")

if __name__ == "__main__":
    get_stat()