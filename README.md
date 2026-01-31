# Psiphon Conduit Cross Platform Setup for Windows , Linux, and macOS

This repository provides a suite of tools designed for users to deploy, monitor, and manage **Psiphon Conduit** on remote Linux servers.

## Download and Preparations
1. **Python Instalation:** Please visist https://www.python.org/downloads/ and install the latest python

2. **Create Directory:** Create a folder named `Conduit` in your `C:\` partition in Windows or /opt/conduit in Linux and macOS environments.
3. **Download Scripts:** Save the following scripts into `C:\Conduit` or /opt/conduit:
   * `deploy_conduit_single_server.py`
   * `deploy_conduit_multi_server.py`
   * `conduit_status.py`
   * `conduit_manager.py`
   * `setup_conduit.bat`
   * `ConduiQt.py`
   
## SSH Genetaion and Python Installation
**Setup:** From the Conduit folder double click on `setup_conduit.bat` for Windows or run `setup_conduit.sh` in terminal. This will generate ssh keys in .ssh folder in user home folder and install the required python packages.

---

## Conduit Deployment
### Running Ineractive GUI
The interactive GUI `ConduitQt.py` is a cross platform designed using PyQt5 and has been tested in Windows, Linux, and macOS Environmnets.  It is designed to do everything you need, to deploy a conduit server, manage and monitor the current status of the server. GUI is self explanatory. You can add new servers and delete your existing servers from a text file names servers.txt. To do the opration simply move one or a group of of the server to list on the right, select them and start doing the operation. When Apply Config Changes is cheked, you can press Start or restart to update the conduit parameters. The rest of the script are invidual applications you can run them for similar funtionalities in Windows.

### Screenshot of the Conduit Manager Qt Application

Here is the GUI interface for Conduit Management:

![Conduit Management Interface](screenshots/ConduitQt1.png)
*(Screenshot showing Conduit management)*

![Conduit Management Interface](screenshots/ConduitQt2.png)
*(Screenshot showing Conduit Statistics faeture)*

### Running Python Scripts
To run any of the Python scripts simply double click on each file or run them in the command line terminal using the py command.

### Single Server
run the following command to deploy to a single target. You will be prompted for the IP address and root password:
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
| **Architecture Mismatch** | you are using a modern Mac with an M1, M2, or M3 chip (Apple Silicon), and you run into issues installing PyQt5| You might need to install it via Homebrew instead of pip|

   ```bash
   brew install pyqt@5
   ```
## Features Note
* **Add server:** Use Add Server(+) if you have not added any server yet. You can also use this later to add further servers.
* **Delete server:** Use Delete Server if you no longer needed.
* **Deploy:** Select one or a number of servers in the right list and cick Deploy. This will deploy your server(s)
* **Status:** Clicking on this dosplay the current status of your server(s), whether it is active or dead.
* **Statistics:** This shows the network analytic
* **Stop:** If you like to stop Conduit service, use this. You hardly need this.
* **Start:** If Conduit service is not active, use this to start it.
* **Re-Start:** If you want to chnage Conduit parameters, like Max Clients or Bandwidth, check Apply Config Changes Checkbox and click Re-start. You can also use this if yours server is not connect after couple of hours.
* **Reset:** You can reset the Conduit config using this. In case if you have not received any client or you think you do not have more clients usually less than 50 for more than a day, you can reset the config. If after frew hours you have receieved any clients you can also reset the config.
* **Display Name/IP:** Use this to siwtch the list to Server name or IP address.
* **Max Clients:** As a rule of thumb, each core should support 50-60 clients. So if you have 4 cores you can set it to 225. This will possibly gives you up to 200 clients.

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




