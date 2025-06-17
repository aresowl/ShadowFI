# ShadowFI
A penetration testing tool for cracking WPA/WPA2/WEP Wi-Fi passwords.
ShadowFI: A Wi-Fi Penetration Testing Tool
About This Project
ShadowFI is a powerful and user-friendly Python script designed for Wi-Fi penetration testing and security assessment of wireless networks. Leveraging the aircrack-ng suite, this tool automates the processes of network scanning, WPA/WPA2 Handshake capture, and attempting to crack WEP/WPA/WPA2 passwords. ShadowFI serves as an excellent educational tool for understanding common Wi-Fi vulnerabilities and network security hardening methods.

Features
Network Scanning: Automatically identifies available Wi-Fi networks within range.

Protocol Support: Capable of targeting WEP, WPA, and WPA2 networks.

Handshake Capture: Performs deauthentication attacks to force clients to disconnect and captures WPA/WPA2 4-way Handshakes.

Wordlist Password Cracking: Utilizes wordlists to attempt password recovery for WPA/WPA2 networks.

WEP Attack Guidance: Guides the user through WEP attacks (Fake Authentication and ARP-Replay) and IV cracking.

Resource Management: Adjusts CPU and I/O priority for the password cracking process to prevent excessive system load.

Simple User Interface: Provides colored output and informative messages for ease of use.

Prerequisites
Before running ShadowFI, ensure the following are installed on your system:

Python 3.x: (3.8 or higher recommended)

Aircrack-ng Suite: Includes airmon-ng, airodump-ng, aireplay-ng, aircrack-ng.

On most Linux distributions (e.g., Ubuntu/Kali), you can install it using:

sudo apt update
sudo apt install aircrack-ng

termcolor Python Package:

pip install termcolor

nice and ionice Utilities: Typically present by default in Linux. (Part of the util-linux package)

Compatible Wireless Adapter: Required for Monitor Mode and Packet Injection. Adapters with chipsets like Realtek RTL8812AU or Ralink RT3070 are generally recommended.

Root Privileges: The script must be executed with root permissions.

Installation and Usage
Clone the Repository:
Clone the project from GitHub to your system:

git clone https://github.com/YOUR_USERNAME/ShadowFI.git
cd ShadowFI

(Replace YOUR_USERNAME with your GitHub username.)

Create and Activate a Virtual Environment (Recommended):

python3 -m venv myenv
source myenv/bin/activate  # For Linux/macOS
# myenv\Scripts\activate.bat  # For Windows Command Prompt
# myenv\Scripts\Activate.ps1  # For Windows PowerShell

Install Dependencies:

pip install -r requirements.txt

Run ShadowFI:
The script must be run with root privileges and using the Python interpreter from your virtual environment. First, find the exact path to the Python interpreter in your virtual environment:

which python3
# Example output: /home/ares/ShadowFI/myenv/bin/python3

Then execute the script:

sudo /path/to/your/myenv/bin/python3 ShadowFI.py
# Example: sudo /home/ares/ShadowFI/myenv/bin/python3 ShadowFI.py

How It Works
Upon execution, ShadowFI automatically follows these steps:

Root Privileges Check: Ensures the script is run with root access.

Monitor Mode Setup: Puts your wireless adapter into monitor mode.

Network Scan: Displays a list of available Wi-Fi networks.

Target Selection: Prompts you to choose a network to attack.

WPA/WPA2 Attack:

Attempts Handshake capture (by sending deauthentication packets to clients).

After capturing the Handshake, attempts to crack the password using the specified wordlist.

WEP Attack:

Guides you to perform Fake Authentication and ARP-Replay attacks in a separate terminal.

Starts IV capture and, upon collecting sufficient IVs, attempts to crack the WEP key.

Cleanup: Restores the system to its original state upon completion or interruption (Ctrl+C).

Wordlist
For successful WPA/WPA2 password cracking, a strong and appropriate wordlist is required. The rockyou.txt file, set by default in the script's WORDLIST_PATH, is a common wordlist but may not be sufficient for complex or region-specific passwords (e.g., Persian passwords).

Recommendations:

Use larger and more diverse wordlists.

Utilize Iran-specific wordlists that include common names, Persian terms, and their combinations (e.g., "Iranian Name Wordlist" or wordlists generated with tools like Cupp based on target information).

Adjust the WORDLIST_PATH in the script to match the path of your chosen wordlist.

CPU Resource Management
ShadowFI utilizes nice and ionice commands, as well as the -j option in aircrack-ng, to reduce CPU and I/O resource consumption during the password cracking operation. This helps your system run smoother during the cracking process and prevents excessive hardware strain. However, be aware that this may increase the cracking duration.

Disclaimer
This ShadowFI tool is designed solely for educational purposes, ethical hacking, and network security assessment. Any unauthorized, illegal, or unethical use of this tool for illicit access to networks or systems is strictly prohibited, and the user bears full responsibility. The developer holds no liability for misuse or damages resulting from this tool. Please adhere to your local laws and regulations.

Author
Developer: Ares

License
This project is licensed under the MIT License. See the LICENSE file for more details.
