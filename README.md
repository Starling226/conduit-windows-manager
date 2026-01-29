# Psiphon Conduit Setup for Windows

This repository provides a suite of tools designed for Windows users to deploy, monitor, and manage **Psiphon Conduit** on remote Linux servers.

## Download and Preparations

1. **Create Directory:** Create a folder named `Conduit` in your `C:\` partition.
2. **Download Scripts:** Save the following scripts into `C:\Conduit`:
   * `deploy_conduit_single_server.py`
   * `deploy_conduit_multi_server.py`
   * `conduit_status.py`
   * `conduit_manager.py`
   * `setup_conduit.bat`
   
## SSH Genetaion and Python Installation
**Setup:** From the Conduit folder double click on `setup_conduit.bat`. This will generate ssh keys in .ssh folder in user home folder and install the required python packages.

---

## Conduit Deployment

### Single Server
Within the cmd terminal run the following command to deploy to a single target. You will be prompted for the IP address and root password:
   ```powershell
   py deploy_conduit_single_server.py
   ```
### Multi Server
For batch deployment, create a file named ip.txt in the C:\Conduit folder. Add one IP address per line. This script assumes all servers share the same root password.

   ```powershell
   py deploy_conduit_multi_server.py
   ```
---

## Management

The `conduit_manager_windows.py` script allows you to check status, stop, start, restart, or reset the service. Sometime even after few hours you have no clients; in that case, you might reset the conduit to get fresh keys and likely get clients.
   ```powershell
   py conduit_manager_windows.py
   ```

### Using servers.txt
For the Management and Monitoring scripts to work with multiple servers, create a `servers.txt` file in the same directory. Please keep the header in top row. default port is 22.

**Format:**
`name,hostname,port,username`

**Example:**
`MyServer,123.45.67.89,22,root`

## Monitoring

After installation, the Psiphon network requires time for vetting and propagation. This can take anywhere from a few minutes to several hours.

To monitor your current server status, run:

   ```powershell
   py conduit_status_windows.py
   ```

Cycle: This script runs every hour by default.

Customization: To change the interval, edit CHECK_INTERVAL_SECONDS (line 14) in conduit_status_windows.py. Do not set this lower than 300 seconds (5 minutes).

---

## Troubleshooting

| Issue | Potential Cause | Solution |
| :--- | :--- | :--- |
| **Connection Timeout** | Firewall is blocking Port 22. | Ensure Port 22 is open in your VPS cloud firewall. |
| **Authentication Failed** | Incorrect password or root disabled. | Ensure `PermitRootLogin yes` is set in `/etc/ssh/sshd_config`. |
| **Permission Denied** | Not logged in as root. | Non-Status actions (Start/Stop/Reset) require root access. |

## Important Notes
* **SSH Port:** These scripts use the standard **SSH Port 22** for all connections.
* **Security Warning:** The `servers.txt` file contains plain-text passwords. **DO NOT** upload this file to GitHub.

---

## Credits & Acknowledgments

This deployment suite is designed for use with the **Conduit** binary provided by [ssmirr](https://github.com/ssmirr/conduit).

* **Binary Source:** [ssmirr/conduit](https://github.com/ssmirr/conduit)
* **Upstream Project:** Based on the original [Psiphon Conduit](https://github.com/Psiphon-Labs/psiphon-conduit) by Psiphon Labs.

---

## Disclaimer

**Use this software at your own risk.** These scripts are provided "as is" without any warranty of any kind. 

* **No Liability:** The author(s) assume **no liability** for loss of data, server downtime, or any damages resulting from the use of this code.
* **Third-Party Binaries:** These scripts are designed to download and install the official **Psiphon Conduit binary**. The author of these scripts is **not responsible** for the maintenance, security, or functionality of the Conduit binary itself.
* **Affiliation:** This project is an independent community tool and is **not** officially affiliated with or endorsed by the Psiphon team.




