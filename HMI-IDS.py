import sys
import socket
import threading
import time
from datetime import datetime
from collections import defaultdict

from PyQt5.QtWidgets import (
    QApplication, QWidget, QLabel, QPushButton, QTextEdit, QVBoxLayout, QHBoxLayout, QMessageBox
)
from PyQt5.QtGui import QFont
from PyQt5.QtCore import QTimer

import psutil
import serial

from scapy.all import sniff, TCP, IP

# === Configuration ===
HMI_PROCESS = "vFactory.exe"          # HMI process name
PASSIVE_COM_PORT = "COM4"             # Mirrored port to listen on
CONTROL_COM_PORT = "COM3"             # Actual COM port for control commands
BAUD_RATE = 9600
LOG_FILE = "host_security_log.txt"

ALLOWED_HOSTNAMES = ["trusted-hostname-1", "trusted-hostname-2"]  # Replace with your allowed hosts
ALLOWED_IPS = ["192.168.1.10", "192.168.1.11" , "192.168.202.150"]                   # Replace with your allowed IPs

# Attack signatures to detect in serial traffic (bytes)
ATTACK_PATTERNS = [
    b"D6 ON",      # Emergency flush command (suspicious if unexpected)
    b"INVALIDCMD", # Example malicious command
    b"OVERFLOW",   # Another example attack signature
    # Add your known attack signatures here
]

# Network detection thresholds
NMAP_SCAN_THRESHOLD = 5     # Number of SYN packets in 10s from same IP to flag Nmap scan
DDOS_PACKET_RATE = 100      # Total packets in 10s to flag DDoS

ip_packet_counts = defaultdict(int)


def check_allowed_host_gui():
    hostname = socket.gethostname()
    ips = socket.gethostbyname_ex(hostname)[2]

    if hostname not in ALLOWED_HOSTNAMES and not any(ip in ALLOWED_IPS for ip in ips):
        app = QApplication(sys.argv)
        msg = QMessageBox()
        msg.setIcon(QMessageBox.Critical)
        msg.setWindowTitle("Unauthorized Host")
        msg.setText(f"Host '{hostname}' with IPs {ips} is NOT authorized to run this application.")
        msg.exec_()
        sys.exit(1)


class HostSecurityMonitor(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Host-Based HMI Security IDS/IPS Monitor")
        self.resize(1100, 700)

        self.passive_serial = None
        self.control_serial = None
        self.running = True
        self.ids_enabled = False

        # UI Elements
        self.process_status_label = QLabel(f"HMI Process Status: Unknown")
        self.com_status_label = QLabel(f"Passive COM Port {PASSIVE_COM_PORT} Status: Unknown")
        self.control_com_status_label = QLabel(f"Control COM Port {CONTROL_COM_PORT} Status: Unknown")
        self.network_status_label = QLabel("Network Status: Monitoring")
        self.alert_label = QLabel("No alerts.")
        self.alert_label.setStyleSheet("color: green; font-weight: bold")

        self.log_view = QTextEdit()
        self.log_view.setFont(QFont("Courier", 10))
        self.log_view.setReadOnly(True)

        # Buttons
        self.ids_toggle_btn = QPushButton("Enable IDS/IPS")
        self.ids_toggle_btn.setCheckable(True)
        self.ids_toggle_btn.clicked.connect(self.toggle_ids)

        self.emergency_btn = QPushButton("Send Emergency Stop (D6 ON)")
        self.emergency_btn.clicked.connect(self.send_emergency_stop)

        self.manual_refresh_btn = QPushButton("Manual Refresh")
        self.manual_refresh_btn.clicked.connect(self.manual_refresh)

        btn_layout = QHBoxLayout()
        btn_layout.addWidget(self.ids_toggle_btn)
        btn_layout.addWidget(self.emergency_btn)
        btn_layout.addWidget(self.manual_refresh_btn)

        layout = QVBoxLayout()
        layout.addWidget(self.process_status_label)
        layout.addWidget(self.com_status_label)
        layout.addWidget(self.control_com_status_label)
        layout.addWidget(self.network_status_label)
        layout.addWidget(self.alert_label)
        layout.addLayout(btn_layout)
        layout.addWidget(self.log_view)
        self.setLayout(layout)

        # Timer and threads
        self.timer = QTimer()
        self.timer.timeout.connect(self.periodic_check)
        self.timer.start(5000)  # every 5 seconds

        threading.Thread(target=self.monitor_hmi_process, daemon=True).start()
        threading.Thread(target=self.listen_passive_port, daemon=True).start()
        threading.Thread(target=self.monitor_control_port, daemon=True).start()
        threading.Thread(target=self.start_network_sniffer, daemon=True).start()
        threading.Thread(target=self.network_ddos_reset_counts, daemon=True).start()

    def log(self, message, alert=False):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        line = f"[{timestamp}] {message}"
        self.log_view.append(line)
        with open(LOG_FILE, "a") as f:
            f.write(line + "\n")

        if alert:
            self.alert_label.setText(f"ALERT: {message}")
            self.alert_label.setStyleSheet("color: red; font-weight: bold")
        else:
            self.alert_label.setText("No alerts.")
            self.alert_label.setStyleSheet("color: green; font-weight: bold")

    def manual_refresh(self):
        self.check_hmi_process()
        self.check_passive_port()
        self.check_control_port()

    def periodic_check(self):
        self.check_hmi_process()
        self.check_passive_port()
        self.check_control_port()

    def monitor_hmi_process(self):
        while self.running:
            self.check_hmi_process()
            time.sleep(3)

    def check_hmi_process(self):
        found = False
        for proc in psutil.process_iter(['name']):
            try:
                if proc.info['name'] and proc.info['name'].lower() == HMI_PROCESS.lower():
                    found = True
                    break
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        if found:
            self.process_status_label.setText(f"HMI Process Status: {HMI_PROCESS} Running")
            self.process_status_label.setStyleSheet("color: green")
            self.log(f"HMI process {HMI_PROCESS} running.")
        else:
            self.process_status_label.setText(f"HMI Process Status: {HMI_PROCESS} NOT Found!")
            self.process_status_label.setStyleSheet("color: red")
            self.log(f"ALERT: HMI process {HMI_PROCESS} not found!", alert=True)

    def listen_passive_port(self):
        while self.running:
            if self.passive_serial is None or not self.passive_serial.is_open:
                try:
                    self.passive_serial = serial.Serial(PASSIVE_COM_PORT, BAUD_RATE, timeout=1)
                    self.log(f"Opened passive tap port {PASSIVE_COM_PORT} for monitoring.")
                    self.com_status_label.setText(f"Passive COM Port {PASSIVE_COM_PORT} Status: Connected")
                    self.com_status_label.setStyleSheet("color: green")
                except Exception as e:
                    self.com_status_label.setText(f"Passive COM Port {PASSIVE_COM_PORT} Status: Disconnected")
                    self.com_status_label.setStyleSheet("color: red")
                    self.log(f"ALERT: Could not open passive tap port {PASSIVE_COM_PORT}: {e}", alert=True)
                    time.sleep(5)
                    continue

            try:
                data = self.passive_serial.read(self.passive_serial.in_waiting or 1)
                if data:
                    hex_data = " ".join(f"{b:02X}" for b in data)
                    ascii_data = "".join(chr(b) if 32 <= b <= 126 else "." for b in data)
                    self.log(f"Passive COM Data >> HEX: {hex_data} | ASCII: {ascii_data}")

                    if self.ids_enabled:
                        for pattern in ATTACK_PATTERNS:
                            if pattern in data:
                                alert_msg = f"Attack signature detected: {pattern.decode(errors='ignore')}"
                                self.log(alert_msg, alert=True)
                                self.trigger_ips_action(pattern)
                                break

            except Exception as e:
                self.log(f"ALERT: Error reading passive COM port: {e}", alert=True)
                try:
                    self.passive_serial.close()
                except:
                    pass
                self.passive_serial = None
                time.sleep(5)

    def monitor_control_port(self):
        while self.running:
            if self.control_serial is None or not self.control_serial.is_open:
                try:
                    self.control_serial = serial.Serial(CONTROL_COM_PORT, BAUD_RATE, timeout=1)
                    self.log(f"Opened control port {CONTROL_COM_PORT} for sending commands.")
                    self.control_com_status_label.setText(f"Control COM Port {CONTROL_COM_PORT} Status: Connected")
                    self.control_com_status_label.setStyleSheet("color: green")
                except Exception as e:
                    self.control_com_status_label.setText(f"Control COM Port {CONTROL_COM_PORT} Status: Disconnected")
                    self.control_com_status_label.setStyleSheet("color: red")
                    self.log(f"ALERT: Could not open control port {CONTROL_COM_PORT}: {e}", alert=True)
                    time.sleep(5)
                    continue
            time.sleep(5)

    def check_passive_port(self):
        if self.passive_serial and self.passive_serial.is_open:
            self.com_status_label.setText(f"Passive COM Port {PASSIVE_COM_PORT} Status: Connected")
            self.com_status_label.setStyleSheet("color: green")
        else:
            self.com_status_label.setText(f"Passive COM Port {PASSIVE_COM_PORT} Status: Disconnected")
            self.com_status_label.setStyleSheet("color: red")

    def check_control_port(self):
        if self.control_serial and self.control_serial.is_open:
            self.control_com_status_label.setText(f"Control COM Port {CONTROL_COM_PORT} Status: Connected")
            self.control_com_status_label.setStyleSheet("color: green")
        else:
            self.control_com_status_label.setText(f"Control COM Port {CONTROL_COM_PORT} Status: Disconnected")
            self.control_com_status_label.setStyleSheet("color: red")

    def trigger_ips_action(self, pattern):
        try:
            if self.control_serial is None or not self.control_serial.is_open:
                self.control_serial = serial.Serial(CONTROL_COM_PORT, BAUD_RATE, timeout=1)
            self.control_serial.write(b"D6 ON\n")
            self.log("IPS: Sent emergency stop command D6 ON to COM3.", alert=True)
        except Exception as e:
            self.log(f"IPS: Failed to send block command: {e}", alert=True)

    def toggle_ids(self, checked):
        self.ids_enabled = checked
        status = "enabled" if checked else "disabled"
        self.log(f"IDS/IPS {status}")

    def send_emergency_stop(self):
        try:
            if self.control_serial is None or not self.control_serial.is_open:
                self.control_serial = serial.Serial(CONTROL_COM_PORT, BAUD_RATE, timeout=1)
            self.control_serial.write(b"D6 ON\n")
            self.log("Manual emergency stop command sent.", alert=True)
        except Exception as e:
            self.log(f"Failed to send emergency stop command: {e}", alert=True)

    def start_network_sniffer(self):
        threading.Thread(target=self.network_sniffer, daemon=True).start()

    def network_sniffer(self):
        def process_packet(pkt):
            if IP in pkt:
                src_ip = pkt[IP].src
                ip_packet_counts[src_ip] += 1

                if pkt.haslayer(TCP):
                    tcp = pkt[TCP]
                    # Detect Nmap SYN scan pattern (SYN only packets)
                    if tcp.flags == "S":  # SYN flag only
                        if ip_packet_counts[src_ip] >= NMAP_SCAN_THRESHOLD:
                            self.log(f"Potential Nmap SYN scan from {src_ip}", alert=True)

        sniff(prn=process_packet, store=0, filter="ip", timeout=None)

    def network_ddos_reset_counts(self):
        while self.running:
            time.sleep(10)
            total_packets = sum(ip_packet_counts.values())
            if total_packets > DDOS_PACKET_RATE:
                self.log(f"DDoS detected: {total_packets} packets in 10 seconds", alert=True)
            ip_packet_counts.clear()


if __name__ == "__main__":
    check_allowed_host_gui()

    app = QApplication(sys.argv)
    monitor = HostSecurityMonitor()
    monitor.show()
    sys.exit(app.exec_())
