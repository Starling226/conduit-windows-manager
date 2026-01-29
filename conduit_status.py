import sys
import re
import time
import os
import statistics
from datetime import datetime, timedelta, timezone
from fabric import Connection, Config
from concurrent.futures import ThreadPoolExecutor, as_completed

# ================= CONFIG =================
SERVER_FILE = "servers.txt"
LOG_FILE = "conduit.log"
MAX_WORKERS = 15
CHECK_INTERVAL_SECONDS = 300 

# Automatically define the key path (Assuming it's in ~/.ssh/id_conduit)
HOME_PATH = os.path.expanduser("~")
SSH_KEY_PATH = os.path.join(HOME_PATH, ".ssh", "id_conduit")
# ==========================================

def strip_ansi(text):
    return re.compile(r'\x1b\[[0-9;]*[a-zA-Z]').sub('', text)

def format_bytes(b):
    if b == 0: return "0 B"
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if b < 1024: return f"{b:.2f} {unit}"
        b /= 1024
    return f"{b:.2f} PB"

def parse_to_bytes(s):
    if s == "N/A" or not s: return 0.0
    match = re.search(r'([\d\.]+)', s)
    if not match: return 0.0
    num = float(match.group(1))
    unit = s.upper()
    if 'TB' in unit: return num * 1024**4
    if 'GB' in unit: return num * 1024**3
    if 'MB' in unit: return num * 1024**2
    if 'KB' in unit: return num * 1024
    return num

def parse_to_float(s):
    if s == "N/A" or not s: return 0.0
    match = re.search(r'([\d\.]+)', s)
    return float(match.group(1)) if match else 0.0

def load_servers(filename, verbose=False):
    """Reads the server file (name, ip, port, user)."""
    servers = []
    if not os.path.exists(filename):
        print(f"[!] Error: {filename} not found."); sys.exit(1)
        
    with open(filename, 'r', encoding='utf-8') as f:
        lines = [line.strip() for line in f if line.strip()]
    
    if verbose:
        print(f"[*] Found {len(lines)-1} servers in {filename}:")
    
    for i, line in enumerate(lines[1:], start=2):
        parts = [p.strip().replace('"', '').replace("'", "") for p in line.split(',')]
        # Updated to handle 4 columns (name, ip, port, user)
        if len(parts) >= 4:
            try:
                s_data = {
                    "name": parts[0], 
                    "hostname": parts[1], 
                    "port": int(parts[2]), 
                    "username": parts[3]
                }
                servers.append(s_data)
                if verbose:
                    print(f"    - {s_data['name']} ({s_data['hostname']})")
            except: pass
    return servers

def get_conduit_status(server):
    result = {"hostname": server["hostname"], "success": False, "status": "N/A", "max_clients": "N/A", "clients": "N/A", "bandwidth": "N/A", "upload": "N/A", "download": "N/A", "uptime": "N/A", "average_download_mbps": "N/A"}
    
    config = Config(overrides={'run': {'pty': True}})
    # Updated to use SSH Key Filename instead of Password
    connect_kwargs = {
        "key_filename": SSH_KEY_PATH,
        "look_for_keys": False, 
        "allow_agent": False
    }

    try:
        with Connection(host=server["hostname"], user=server["username"], port=server["port"], connect_kwargs=connect_kwargs, config=config) as conn:
            try:
                res = conn.run("/opt/conduit/conduit service status -f", hide=True, timeout=10)
                output = res.stdout
            except Exception as e:
                output = getattr(e.result, 'stdout', str(e)) if hasattr(e, 'result') else str(e)
            
            clean = strip_ansi(output)
            if "Status:" not in clean: return result
            result["success"] = True
            
            def get_last(pat, txt):
                found = re.findall(pat, txt, re.IGNORECASE)
                return found[-1].strip() if found else "N/A"

            result["status"] = get_last(r"Status:\s*(\w+)", clean)
            result["clients"] = get_last(r"Clients:\s*(\d+)", clean)
            result["upload"] = get_last(r"Upload:\s*([\d\.]+ [TGMK]?B)", clean)
            result["download"] = get_last(r"Download:\s*([\d\.]+ [TGMK]?B)", clean)
            result["uptime"] = get_last(r"Uptime:\s*([\dhm\s]+s)", clean)
            
            m_max = re.search(r"Max Clients:\s*(\d+)", clean, re.IGNORECASE)
            result["max_clients"] = m_max.group(1) if m_max else "N/A"
            m_bw = re.search(r"Bandwidth:\s*([^\n\r\t]+)", clean, re.IGNORECASE)
            result["bandwidth"] = m_bw.group(1).strip()[:10] if m_bw else "N/A"

            if result["download"] != "N/A" and result["uptime"] != "N/A":
                try:
                    d_bytes = parse_to_bytes(result["download"])
                    uptime_str = result["uptime"]
                    h = int(re.search(r'(\d+)h', uptime_str).group(1)) if 'h' in uptime_str else 0
                    m = int(re.search(r'(\d+)m', uptime_str).group(1)) if 'm' in uptime_str else 0
                    s = int(re.search(r'(\d+)s', uptime_str).group(1)) if 's' in uptime_str else 0
                    total_sec = (h * 3600) + (m * 60) + s
                    if total_sec > 0:
                        result["average_download_mbps"] = f"{(d_bytes * 8) / total_sec / 10**6:.2f} Mbps"
                except: pass
    except: pass
    return result

def run_cycle():
    SERVERS = load_servers(SERVER_FILE, verbose=False)
    results = []
    
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(get_conduit_status, s): s for s in SERVERS}
        for f in as_completed(futures): results.append(f.result())

    results = sorted(results, key=lambda x: parse_to_float(x["average_download_mbps"]), reverse=True)
    iran_time = datetime.now(timezone.utc) + timedelta(hours=3, minutes=30)
    ts = iran_time.strftime('%Y-%m-%d %H:%M:%S')
    
    out = [f"\n{'='*130}", f"CONDUIT REPORT - {ts}", f"{'='*130}"]
    out.append("┌──────────────────────────────────────┬─────────────┬────────────┬─────────┬────────────┬────────────┬────────────┬────────────┬─────────────────────┐")
    out.append("│ Hostname                             │ Status      │ Max Clients│ Clients │ Bandwidth  │ Upload     │ Download   │ Uptime     │ Avg Download Mbps   │")
    out.append("├──────────────────────────────────────┼─────────────┼────────────┼─────────┼────────────┼────────────┼────────────┼────────────┼─────────────────────┤")
    
    total_clients = 0
    valid_results = [r for r in results if r["success"]]
    for r in results:
        status = "✓ Connected" if r["success"] else "✗ Error"
        if r["success"] and r["clients"] != "N/A": 
            try: total_clients += int(r["clients"])
            except: pass
        out.append(f"│ {r['hostname']:<36} │ {status:<11} │ {r['max_clients']:<10} │ {r['clients']:<7} │ {r['bandwidth']:<10} │ {r['upload']:<10} │ {r['download']:<10} │ {r['uptime']:<10} │ {r['average_download_mbps']:<19} │")
    out.append("└──────────────────────────────────────┴─────────────┴────────────┴─────────┴────────────┴────────────┴────────────┴────────────┴─────────────────────┘")
    
    out.append(f"\n--- Analytics Summary (Iran Time: {ts}) ---")
    out.append(f"Total number of Clients across all servers: {total_clients}\n")
    out.append(f"{'Metric':<12} │ {'Mean':<12} │ {'Median':<12} │ {'Min':<12} │ {'Max':<12}")
    sep_line = f"{'─'*13}┼{'─'*14}┼{'─'*14}┼{'─'*14}┼{'─'*14}"
    out.append(sep_line)

    def get_stat_row(label, data_list, is_bytes=False):
        if not data_list: return ""
        avg_val, med_val, min_val, max_val = statistics.mean(data_list), statistics.median(data_list), min(data_list), max(data_list)
        if is_bytes:
            return f"{label:<12} │ {format_bytes(avg_val):<12} │ {format_bytes(med_val):<12} │ {format_bytes(min_val):<12} │ {format_bytes(max_val):<12}"
        if label == "Clients":
            return f"{label:<12} │ {int(round(avg_val)):<12} │ {int(round(med_val)):<12} │ {int(min_val):<12} │ {int(max_val):<12}"
        return f"{label:<12} │ {avg_val:<12.2f} │ {med_val:<12.2f} │ {min_val:<12.2f} │ {max_val:<12.2f} Mbps"

    if valid_results:
        clients_list = [int(r["clients"]) for r in valid_results if r["clients"] != "N/A"]
        ups = [parse_to_bytes(r["upload"]) for r in valid_results]
        downs = [parse_to_bytes(r["download"]) for r in valid_results]
        mbps_list = [parse_to_float(r["average_download_mbps"]) for r in valid_results]
        out.append(get_stat_row("Clients", clients_list))
        out.append(get_stat_row("Upload", ups, True))
        out.append(get_stat_row("Download", downs, True))
        out.append(get_stat_row("Avg Mbps", mbps_list))

    out.append("\n")
    report = "\n".join(out)
    with open(LOG_FILE, "a", encoding="utf-8") as f: f.write(report + "\n")
    print(report)

if __name__ == "__main__":
    print(f"{'='*50}")
    print(f"        CONDUIT MONITORING INITIALIZATION")
    print(f"{'='*50}")
    
    # Check for key existence first
    if not os.path.exists(SSH_KEY_PATH):
        print(f"[!] Warning: SSH Key not found at {SSH_KEY_PATH}")
        print("[!] Ensure you have generated the key or updated the script config.")
    
    load_servers(SERVER_FILE, verbose=True)
    
    print(f"\n[*] Logging active: {LOG_FILE}")
    print("[!] Press Ctrl+C to exit.\n")
    
    try:
        while True:
            run_cycle()
            next_check = (datetime.now() + timedelta(seconds=CHECK_INTERVAL_SECONDS)).strftime('%H:%M:%S')
            print(f"[*] Cycle finished. Next update at {next_check}.")
            time.sleep(CHECK_INTERVAL_SECONDS)
    except KeyboardInterrupt:
        print("\n[!] Exiting gracefully...")