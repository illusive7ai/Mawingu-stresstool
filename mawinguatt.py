# Mawinguatt.py - Mawingu Attacker
import sys
import os
import json
import hashlib
import shutil
import csv
import io
import threading
import time
import subprocess
import platform
import socket
import random
import struct
from datetime import datetime, timedelta

# IMPORTANT: Set Qt.AA_ShareOpenGLContexts BEFORE importing PyQt5 modules
os.environ['QT_QPA_PLATFORM'] = 'windows' 

# Set the attribute before creating QApplication
from PyQt5.QtCore import Qt, QCoreApplication, QTimer, QPropertyAnimation, QEasingCurve, pyqtProperty, QRect, QPoint, QSize, QUrl, QThread, pyqtSignal
QCoreApplication.setAttribute(Qt.AA_ShareOpenGLContexts, True)

# Now import other PyQt5 modules
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
from PyQt5.QtGui import *
from PyQt5.QtWebEngineWidgets import QWebEngineView  # For HTML content

SECTION_COLORS = {
    "portscan": {
        "primary": "#3b82f6",
        "secondary": "#1d4ed8",
        "bg": "rgba(59, 130, 246, 0.15)",
        "border": "rgba(59, 130, 246, 0.3)",
        "text": "#60a5fa",
        "light": "#93c5fd"
    },
    "icmp": {
        "primary": "#10b981",
        "secondary": "#059669",
        "bg": "rgba(16, 185, 129, 0.15)",
        "border": "rgba(16, 185, 129, 0.3)",
        "text": "#34d399",
        "light": "#6ee7b7"
    },
    "dns": {
        "primary": "#8b5cf6",
        "secondary": "#7c3aed",
        "bg": "rgba(139, 92, 246, 0.15)",
        "border": "rgba(139, 92, 246, 0.3)",
        "text": "#a78bfa",
        "light": "#c4b5fd"
    }
}

# Base dark theme colors
BASE_BG = "#0f172a"
CARD_BG = "rgba(15, 23, 42, 0.85)"
TEXT_PRIMARY = "#f1f5f9"
TEXT_SECONDARY = "#cbd5e1"
TEXT_MUTED = "#94a3b8"
BORDER_COLOR = "rgba(148, 163, 184, 0.2)"


class DNSAttackWorker(QThread):
    """Worker thread for DNS attack operations"""
    attack_update = pyqtSignal(int, int, int)  # sent, success, failed
    attack_response = pyqtSignal(str, str, str)  # target, response, query_type
    attack_progress = pyqtSignal(int, int)  # current, total
    attack_started = pyqtSignal(str, str, int)  # target, query_type, total_attacks
    attack_complete = pyqtSignal(dict)  # statistics
    
    def __init__(self, dns_server, query_type="A", attack_count=-1, timeout=2):
        super().__init__()
        self.dns_server = dns_server
        self.query_type = query_type
        self.attack_count = attack_count  # -1 for infinite
        self.timeout = timeout
        self.stop_flag = False
        self.sent_attacks = 0
        self.successful_attacks = 0
        self.failed_attacks = 0
        self.lock = threading.Lock()
        
        # Common domains for DNS queries
        self.test_domains = [
            "google.com", "facebook.com", "youtube.com", "yahoo.com",
            "amazon.com", "wikipedia.org", "twitter.com", "instagram.com",
            "linkedin.com", "microsoft.com", "apple.com", "netflix.com",
            "reddit.com", "ebay.com", "bing.com", "live.com",
            "msn.com", "office.com", "outlook.com", "adobe.com"
        ]
        
    def run(self):
        """Main DNS attack loop"""
        self.sent_attacks = 0
        self.successful_attacks = 0
        self.failed_attacks = 0
        
        self.attack_started.emit(self.dns_server, self.query_type, self.attack_count)
        
        attack_number = 0
        
        if self.attack_count == -1:
            # Infinite mode
            while not self.stop_flag:
                attack_number += 1
                self._send_dns_query(attack_number)
                if not self.stop_flag:
                    self.attack_update.emit(self.sent_attacks, self.successful_attacks, self.failed_attacks)
                    # Small delay to avoid overwhelming
                    time.sleep(0.05)
        else:
            # Finite mode
            total_attacks = self.attack_count
            for attack_number in range(1, total_attacks + 1):
                if self.stop_flag:
                    break
                self._send_dns_query(attack_number)
                self.attack_progress.emit(attack_number, total_attacks)
                self.attack_update.emit(self.sent_attacks, self.successful_attacks, self.failed_attacks)
                # Small delay to avoid overwhelming
                if not self.stop_flag and attack_number < total_attacks:
                    time.sleep(0.05)
        
        # Send final statistics
        stats = {
            "sent": self.sent_attacks,
            "successful": self.successful_attacks,
            "failed": self.failed_attacks,
            "target": self.dns_server,
            "query_type": self.query_type,
            "total": self.attack_count if self.attack_count != -1 else self.sent_attacks
        }
        self.attack_complete.emit(stats)
    
    def _send_dns_query(self, attack_id):
        """Send a DNS query to the target DNS server"""
        if self.stop_flag:
            return
        
        try:
            # Select a random domain for the query
            domain = random.choice(self.test_domains)
            
            # Create a DNS query packet
            query_packet = self._create_dns_query(domain, self.query_type)
            
            # Send the DNS query
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            
            start_time = time.time()
            sock.sendto(query_packet, (self.dns_server, 53))
            
            # Wait for response
            try:
                response, addr = sock.recvfrom(1024)
                response_time = (time.time() - start_time) * 1000  # in milliseconds
                
                # Parse response
                if self._parse_dns_response(response):
                    with self.lock:
                        self.successful_attacks += 1
                        self.sent_attacks += 1
                        response_text = f"✓ DNS response from {self.dns_server} for {domain} ({response_time:.1f}ms)"
                        self.attack_response.emit(self.dns_server, response_text, self.query_type)
                else:
                    with self.lock:
                        self.failed_attacks += 1
                        self.sent_attacks += 1
                        response_text = f"✗ Invalid DNS response from {self.dns_server} for {domain}"
                        self.attack_response.emit(self.dns_server, response_text, self.query_type)
                        
            except socket.timeout:
                with self.lock:
                    self.failed_attacks += 1
                    self.sent_attacks += 1
                    response_text = f"✗ Timeout - No response from {self.dns_server} for {domain}"
                    self.attack_response.emit(self.dns_server, response_text, self.query_type)
            
            sock.close()
            
        except Exception as e:
            with self.lock:
                self.failed_attacks += 1
                self.sent_attacks += 1
                self.attack_response.emit(self.dns_server, f"✗ Error: {str(e)}", self.query_type)
    
    def _create_dns_query(self, domain, query_type):
        """Create a DNS query packet"""
        # Transaction ID (random)
        transaction_id = random.randint(0, 65535)
        
        # Flags: Standard query (0x0100)
        flags = 0x0100
        
        # Questions: 1
        questions = 1
        
        # Answer RRs: 0
        answer_rrs = 0
        
        # Authority RRs: 0
        authority_rrs = 0
        
        # Additional RRs: 0
        additional_rrs = 0
        
        # Pack header
        header = struct.pack('!HHHHHH', transaction_id, flags, questions, answer_rrs, authority_rrs, additional_rrs)
        
        # Pack domain name
        domain_parts = domain.split('.')
        domain_encoded = b''
        for part in domain_parts:
            domain_encoded += bytes([len(part)]) + part.encode()
        domain_encoded += b'\x00'
        
        # Query type and class
        qtype = 1 if query_type.upper() == 'A' else 28 if query_type.upper() == 'AAAA' else 1  # A record by default
        qclass = 1  # IN class
        
        question = domain_encoded + struct.pack('!HH', qtype, qclass)
        
        return header + question
    
    def _parse_dns_response(self, response):
        """Parse DNS response to check if it's valid"""
        try:
            if len(response) < 12:
                return False
            
            # Check flags for response
            flags = struct.unpack('!H', response[2:4])[0]
            
            # Check if QR bit is set (response)
            if flags & 0x8000:
                # Check response code (last 4 bits of flags)
                rcode = flags & 0x000F
                # rcode 0 means no error
                return rcode == 0
            
            return False
        except:
            return False
    
    def stop(self):
        """Stop the DNS attack"""
        self.stop_flag = True


class DNSTerminal(QTextEdit):
    """Custom terminal for DNS attack output"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setReadOnly(True)
        self.setFont(QFont("Consolas", 9))
        self.setStyleSheet("""
            DNSTerminal {
                background: #0a0c10;
                border: 2px solid rgba(139, 92, 246, 0.3);
                border-radius: 6px;
                color: #a78bfa;
                font-family: Consolas, monospace;
                font-size: 10px;
                padding: 8px;
            }
        """)
        
        self.setPlainText("> DNS Attack Terminal Ready\n> Enter target DNS server and number of attacks to begin\n")
    
    def append_attack_result(self, target, result_text, query_type):
        """Append a DNS attack result to the terminal"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        color = "#a78bfa" if "✓" in result_text else "#f87171" if "✗" in result_text else "#fbbf24"
        self.append(f'<span style="color: {color};">[{timestamp}] [{target}] {result_text}</span>')
        scrollbar = self.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())
    
    def append_system_message(self, message, msg_type="info"):
        """Append system messages like start/stop"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        color = "#a78bfa" if msg_type == "info" else "#fbbf24" if msg_type == "warning" else "#10b981"
        self.append(f'<span style="color: {color};">[{timestamp}] [SYSTEM] {message}</span>')
        scrollbar = self.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())
    
    def clear_terminal(self):
        """Clear the terminal display"""
        self.clear()
        self.append("> DNS Attack Terminal Ready\n> Terminal cleared")


class PortScanWorker(QThread):
    """Worker thread for port scanning operations"""
    port_update = pyqtSignal(int, int, str)  # port, status, service
    scan_progress = pyqtSignal(int, int)  # current, total
    scan_complete = pyqtSignal(list)  # list of open ports
    scan_started = pyqtSignal(str, int, int)  # target, start_port, end_port
    
    def __init__(self, target_ip, start_port, end_port, scan_type="connect", timeout=2, max_threads=100):
        super().__init__()
        self.target_ip = target_ip
        self.start_port = start_port
        self.end_port = end_port
        self.scan_type = scan_type  # "connect" or "syn"
        self.timeout = timeout
        self.max_threads = max_threads
        self.stop_flag = False
        self.open_ports = []
        
    def run(self):
        """Main port scanning loop"""
        self.open_ports = []
        total_ports = self.end_port - self.start_port + 1
        
        self.scan_started.emit(self.target_ip, self.start_port, self.end_port)
        
        # Use threading for faster scanning
        with threading.BoundedSemaphore(self.max_threads):
            threads = []
            for port in range(self.start_port, self.end_port + 1):
                if self.stop_flag:
                    break
                    
                thread = threading.Thread(target=self.scan_port, args=(port,))
                thread.start()
                threads.append(thread)
                
                # Update progress
                current_port = port - self.start_port + 1
                self.scan_progress.emit(current_port, total_ports)
                
                # Small delay to avoid overwhelming the network
                if self.scan_type == "connect":
                    time.sleep(0.01)
            
            # Wait for all threads to complete
            for thread in threads:
                thread.join()
        
        self.scan_complete.emit(self.open_ports)
    
    def scan_port(self, port):
        """Scan a single port"""
        if self.stop_flag:
            return
            
        try:
            if self.scan_type == "connect":
                # TCP Connect scan - more reliable and detectable
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                result = sock.connect_ex((self.target_ip, port))
                
                if result == 0:
                    # Port is open - try to identify service
                    service = self.get_service_name(port)
                    self.open_ports.append(port)
                    self.port_update.emit(port, 1, service)
                else:
                    # Port is closed or filtered
                    self.port_update.emit(port, 0, "")
                
                sock.close()
                
            elif self.scan_type == "syn":
                # SYN scan (half-open) - more stealthy but requires root/admin
                # This is a simplified version - real SYN scan requires raw sockets
                # For Windows, we'll use a different approach
                if platform.system().lower() == "windows":
                    # Fall back to connect scan on Windows
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(self.timeout)
                    result = sock.connect_ex((self.target_ip, port))
                    
                    if result == 0:
                        service = self.get_service_name(port)
                        self.open_ports.append(port)
                        self.port_update.emit(port, 1, service)
                    else:
                        self.port_update.emit(port, 0, "")
                    
                    sock.close()
                else:
                    # On Linux, we could use scapy or raw sockets for real SYN scan
                    # For now, we'll use connect scan with a note
                    self.port_update.emit(port, 2, "SYN scan requires admin/root")
                    
        except Exception as e:
            self.port_update.emit(port, -1, str(e))
    
    def get_service_name(self, port):
        """Get common service name for a port"""
        common_ports = {
            20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
            53: "DNS", 80: "HTTP", 110: "POP3", 111: "RPC", 135: "RPC",
            139: "NetBIOS", 143: "IMAP", 443: "HTTPS", 445: "SMB",
            993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 3306: "MySQL",
            3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 8080: "HTTP-Alt",
            8443: "HTTPS-Alt", 27017: "MongoDB"
        }
        return common_ports.get(port, "unknown")
    
    def stop(self):
        """Stop the port scan"""
        self.stop_flag = True


class PingWorker(QThread):
    """Worker thread for ping flooding operations - FIXED to use os.system like working version"""
    ping_update = pyqtSignal(int, int, int)  # sent, success, failed
    ping_reply = pyqtSignal(str, str)  # target, reply_text
    finished = pyqtSignal()
    
    def __init__(self, targets, ping_count, interval):
        super().__init__()
        self.targets = targets
        self.ping_count = ping_count
        self.interval = interval
        self.stop_flag = False
        self.sent_pings = 0
        self.successful_pings = 0
        self.failed_pings = 0
        self.lock = threading.Lock()
        
    def run(self):
        """Main ping flood loop"""
        self.sent_pings = 0
        self.successful_pings = 0
        self.failed_pings = 0
        
        # Determine OS for ping command
        is_windows = platform.system().lower() == "windows"
        
        if self.ping_count == -1:
            # Infinite mode
            while not self.stop_flag:
                for target in self.targets:
                    if self.stop_flag:
                        break
                    self._send_ping(target, is_windows)
                    if self.interval > 0:
                        time.sleep(self.interval)
                # Update UI after each round
                self.ping_update.emit(self.sent_pings, self.successful_pings, self.failed_pings)
        else:
            # Finite mode
            total_to_send = self.ping_count * len(self.targets)
            pings_sent = 0
            
            while pings_sent < total_to_send and not self.stop_flag:
                for target in self.targets:
                    if pings_sent >= total_to_send or self.stop_flag:
                        break
                    self._send_ping(target, is_windows)
                    pings_sent += 1
                    if self.interval > 0 and pings_sent < total_to_send:
                        time.sleep(self.interval)
                self.ping_update.emit(self.sent_pings, self.successful_pings, self.failed_pings)
        
        self.finished.emit()
    
    def _send_ping(self, target, is_windows):
        """Send a single ping - FIXED to match working version exactly"""
        if self.stop_flag:
            return
        
        try:
            # Use the exact same method as the working code
            if is_windows:
                # Windows ping command
                cmd = f"ping {target} -n 1"
            else:
                # Linux/Mac ping command
                cmd = f"ping {target} -c 1"
            
            # Execute ping and capture result
            result = os.system(cmd)
            
            # Check if ping was successful (return code 0 means success)
            with self.lock:
                if result == 0:
                    self.successful_pings += 1
                    self.sent_pings += 1
                    reply_text = f"✓ Reply from {target}"
                    self.ping_reply.emit(target, reply_text)
                else:
                    self.failed_pings += 1
                    self.sent_pings += 1
                    reply_text = f"✗ No response from {target}"
                    self.ping_reply.emit(target, reply_text)
                    
        except Exception as e:
            with self.lock:
                self.failed_pings += 1
                self.sent_pings += 1
                self.ping_reply.emit(target, f"✗ Error: {str(e)}")
    
    def stop(self):
        """Stop the ping flood"""
        self.stop_flag = True


class TerminalTextEdit(QTextEdit):
    """Custom text edit widget styled like a terminal for ping output"""
    
    def __init__(self, section="icmp", parent=None):
        super().__init__(parent)
        colors = SECTION_COLORS.get(section, SECTION_COLORS["icmp"])
        
        self.setReadOnly(True)
        self.setFont(QFont("Consolas", 9))
        self.setStyleSheet(f"""
            TerminalTextEdit {{
                background: #0a0c10;
                border: 2px solid {colors['border']};
                border-radius: 6px;
                color: #00ffaa;
                font-family: Consolas, monospace;
                font-size: 10px;
                padding: 8px;
            }}
            TerminalTextEdit:focus {{
                border: 2px solid {colors['primary']};
            }}
        """)
        
        self.setPlainText("> ICMP Attack Terminal Ready\n> Enter target(s) and click Start Flood\n")
    
    def append_ping_result(self, target, result_text):
        """Append a ping result to the terminal"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.append(f"[{timestamp}] [{target}] {result_text}")
        scrollbar = self.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())
    
    def append_system_message(self, message, msg_type="info"):
        """Append system messages like start/stop"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.append(f"[{timestamp}] [SYSTEM] {message}")
        scrollbar = self.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())
    
    def clear_terminal(self):
        """Clear the terminal display"""
        self.clear()
        self.append("> ICMP Attack Terminal Ready\n> Terminal cleared")


class PortScanTerminal(QTextEdit):
    """Custom terminal for port scan output"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setReadOnly(True)
        self.setFont(QFont("Consolas", 9))
        self.setStyleSheet("""
            PortScanTerminal {
                background: #0a0c10;
                border: 2px solid rgba(59, 130, 246, 0.3);
                border-radius: 6px;
                color: #60a5fa;
                font-family: Consolas, monospace;
                font-size: 10px;
                padding: 8px;
            }
        """)
        
        self.setPlainText("> Port Scanner Terminal Ready\n> Enter target IP and port range to begin scanning\n")
    
    def append_scan_result(self, port, status, service):
        """Append a port scan result"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        if status == 1:
            status_text = "OPEN"
            color = "#10b981"
        elif status == 0:
            status_text = "CLOSED"
            color = "#ef4444"
        elif status == 2:
            status_text = "WARNING"
            color = "#f59e0b"
        else:
            status_text = "ERROR"
            color = "#ef4444"
        
        formatted_line = f'<span style="color: {color};">[{timestamp}] PORT {port} - {status_text}</span>'
        if service and status == 1:
            formatted_line += f' <span style="color: #60a5fa;">[{service}]</span>'
        
        self.append(formatted_line)
        scrollbar = self.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())
    
    def append_system_message(self, message, msg_type="info"):
        """Append system messages"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        color = "#60a5fa" if msg_type == "info" else "#f59e0b" if msg_type == "warning" else "#10b981"
        self.append(f'<span style="color: {color};">[{timestamp}] [SYSTEM] {message}</span>')
        scrollbar = self.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())
    
    def clear_terminal(self):
        """Clear the terminal display"""
        self.clear()
        self.append("> Port Scanner Terminal Ready\n> Terminal cleared")


class GlassCardWidget(QFrame):
    """Glass morphism card widget with section-specific theming"""
    
    def __init__(self, parent=None, section="portscan"):
        super().__init__(parent)
        self.section = section
        colors = SECTION_COLORS.get(section, SECTION_COLORS["portscan"])
        
        self.setStyleSheet(f"""
            GlassCardWidget {{
                background: {CARD_BG};
                border: 1px solid {colors['border']};
                border-radius: 8px;
            }}
        """)


class StatCardWidget(GlassCardWidget):
    """Statistics card with icon and value - section themed"""
    
    def __init__(self, title, icon_svg=None, section="portscan", parent=None):
        super().__init__(parent, section)
        self.section = section
        colors = SECTION_COLORS.get(section, SECTION_COLORS["portscan"])
        
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(8)
        
        if icon_svg:
            icon_label = QLabel(icon_svg)
            icon_label.setStyleSheet(f"font-size: 20px; color: {colors['primary']};")
            layout.addWidget(icon_label)
        
        title_label = QLabel(title)
        title_label.setStyleSheet(f"color: {TEXT_MUTED}; font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: 1px;")
        layout.addWidget(title_label)
        
        self.value_label = QLabel("0")
        self.value_label.setStyleSheet(f"color: {TEXT_PRIMARY}; font-size: 24px; font-weight: 700;")
        layout.addWidget(self.value_label)
        
        layout.addStretch()
    
    def set_value(self, value):
        self.value_label.setText(str(value))


class PrimaryButton(QPushButton):
    """Primary gradient button - section themed"""
    
    def __init__(self, text, icon_text=None, section="portscan", parent=None):
        super().__init__(text, parent)
        self.section = section
        colors = SECTION_COLORS.get(section, SECTION_COLORS["portscan"])
        
        self.setCursor(Qt.PointingHandCursor)
        self.setFixedHeight(36)
        self.setMinimumWidth(100)
        
        self.setStyleSheet(f"""
            PrimaryButton {{
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 {colors['primary']}, stop:1 {colors['secondary']});
                color: white;
                border: none;
                border-radius: 6px;
                font-weight: 600;
                font-size: 12px;
                padding: 6px 16px;
            }}
            PrimaryButton:hover {{
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 {colors['light']}, stop:1 {colors['primary']});
            }}
            PrimaryButton:pressed {{
                background: {colors['secondary']};
            }}
        """)
        
        if icon_text:
            self.setText(f"{icon_text}  {text}")


class SecondaryButton(QPushButton):
    """Secondary button with border - section themed"""
    
    def __init__(self, text, icon_text=None, section="portscan", parent=None):
        super().__init__(text, parent)
        self.section = section
        colors = SECTION_COLORS.get(section, SECTION_COLORS["portscan"])
        
        self.setCursor(Qt.PointingHandCursor)
        self.setFixedHeight(36)
        self.setMinimumWidth(100)
        
        self.setStyleSheet(f"""
            SecondaryButton {{
                background: transparent;
                color: {colors['text']};
                border: 2px solid {colors['border']};
                border-radius: 6px;
                font-weight: 600;
                font-size: 12px;
                padding: 6px 16px;
            }}
            SecondaryButton:hover {{
                background: {colors['bg']};
                border: 2px solid {colors['primary']};
            }}
            SecondaryButton:pressed {{
                background: {colors['border']};
            }}
        """)
        
        if icon_text:
            self.setText(f"{icon_text}  {text}")


class DangerButton(QPushButton):
    """Danger button for destructive actions"""
    
    def __init__(self, text, icon_text=None, parent=None):
        super().__init__(text, parent)
        self.setCursor(Qt.PointingHandCursor)
        self.setFixedHeight(36)
        self.setMinimumWidth(100)
        self.setStyleSheet("""
            DangerButton {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #ef4444, stop:1 #dc2626);
                color: white;
                border: none;
                border-radius: 6px;
                font-weight: 600;
                font-size: 12px;
                padding: 6px 16px;
            }
            DangerButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #f87171, stop:1 #ef4444);
            }
            DangerButton:pressed {
                background: #b91c1c;
            }
        """)
        
        if icon_text:
            self.setText(f"{icon_text}  {text}")


class SidebarButton(QPushButton):
    """Sidebar navigation button with section-specific active colors"""
    
    def __init__(self, text, icon_char, section="portscan", parent=None):
        super().__init__(text, parent)
        self.section = section
        self.colors = SECTION_COLORS.get(section, SECTION_COLORS["portscan"])
        self.icon_char = icon_char
        
        self.setCursor(Qt.PointingHandCursor)
        self.setFixedHeight(44)
        self.setCheckable(True)
        self.update_style(False)
    
    def update_style(self, is_active):
        if is_active:
            self.setStyleSheet(f"""
                SidebarButton {{
                    text-align: left;
                    background: {self.colors['bg']};
                    border: none;
                    border-left: 3px solid {self.colors['primary']};
                    color: {self.colors['text']};
                    font-size: 13px;
                    font-weight: 600;
                    padding-left: 50px;
                    padding-right: 20px;
                }}
            """)
        else:
            self.setStyleSheet(f"""
                SidebarButton {{
                    text-align: left;
                    background: transparent;
                    border: none;
                    border-left: 3px solid transparent;
                    color: {TEXT_MUTED};
                    font-size: 13px;
                    font-weight: 500;
                    padding-left: 50px;
                    padding-right: 20px;
                }}
                SidebarButton:hover {{
                    background: rgba(255, 255, 255, 0.05);
                    color: {TEXT_SECONDARY};
                }}
            """)
    
    def paintEvent(self, event):
        super().paintEvent(event)
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        painter.setPen(QColor(self.colors['primary'] if self.isChecked() else TEXT_MUTED))
        font = QFont("Segoe UI", 13)
        painter.setFont(font)
        painter.drawText(QRect(20, 0, 24, self.height()), Qt.AlignCenter, self.icon_char if self.icon_char else "•")


class AvatarWidget(QWidget):
    """Avatar widget with fixed relative path in assets folder"""
    
    def __init__(self, size=70, parent=None):
        super().__init__(parent)
        self.setFixedSize(size, size)
        self.avatar_image = None
        self.initials = "A"
        self.load_avatar()
    
    def load_avatar(self):
        try:
            script_dir = os.path.dirname(os.path.abspath(__file__))
            avatar_path = os.path.join(script_dir, "assets", "attacker.png")
            
            if os.path.exists(avatar_path):
                pixmap = QPixmap(avatar_path)
                if not pixmap.isNull():
                    self.avatar_image = pixmap.scaled(
                        self.size(), 
                        Qt.KeepAspectRatioByExpanding, 
                        Qt.SmoothTransformation
                    )
                    self.update()
        except Exception as e:
            print(f"Error loading avatar: {e}")
    
    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        
        if self.avatar_image:
            path = QPainterPath()
            path.addEllipse(0, 0, self.width(), self.height())
            painter.setClipPath(path)
            painter.drawPixmap(QRect(0, 0, self.width(), self.height()), self.avatar_image)
        else:
            gradient = QLinearGradient(0, 0, self.width(), self.height())
            gradient.setColorAt(0, QColor("#ef4444"))
            gradient.setColorAt(1, QColor("#dc2626"))
            painter.setBrush(gradient)
            painter.setPen(Qt.NoPen)
            painter.drawEllipse(0, 0, self.width(), self.height())
            painter.setPen(QColor("#ffffff"))
            font = QFont("Segoe UI", int(self.width() / 2.5), QFont.Bold)
            painter.setFont(font)
            painter.drawText(self.rect(), Qt.AlignCenter, self.initials)


class ToastNotification(QFrame):
    """Enhanced toast notification"""
    
    def __init__(self, message, type_="success", parent=None, section="portscan"):
        super().__init__(parent)
        self.setWindowFlags(Qt.FramelessWindowHint | Qt.ToolTip)
        self.setAttribute(Qt.WA_TranslucentBackground)
        
        colors = SECTION_COLORS.get(section, SECTION_COLORS["portscan"])
        
        type_colors = {
            "success": {"bg": "rgba(34, 197, 94, 0.9)", "icon": "✓"},
            "error": {"bg": "rgba(239, 68, 68, 0.9)", "icon": "✗"},
            "warning": {"bg": "rgba(245, 158, 11, 0.9)", "icon": "⚠"},
            "info": {"bg": colors['primary'], "icon": "ℹ"}
        }
        
        color = type_colors.get(type_, type_colors["info"])
        
        layout = QHBoxLayout(self)
        layout.setContentsMargins(12, 10, 12, 10)
        layout.setSpacing(10)
        
        icon_label = QLabel(color['icon'])
        icon_label.setStyleSheet("font-size: 14px; color: white;")
        layout.addWidget(icon_label)
        
        msg_label = QLabel(message)
        msg_label.setStyleSheet("color: white; font-size: 12px; font-weight: 500;")
        layout.addWidget(msg_label)
        
        self.setStyleSheet(f"""
            ToastNotification {{
                background: {color['bg']};
                border-radius: 6px;
                border: 1px solid rgba(255, 255, 255, 0.2);
            }}
        """)


class ModernLineEdit(QLineEdit):
    """Modern styled line edit"""
    
    def __init__(self, placeholder="", section="portscan", parent=None):
        super().__init__(parent)
        colors = SECTION_COLORS.get(section, SECTION_COLORS["portscan"])
        
        self.setPlaceholderText(placeholder)
        self.setFixedHeight(40)  # Increased from 38
        self.setStyleSheet(f"""
            ModernLineEdit {{
                background: rgba(30, 41, 59, 0.6);
                border: 2px solid {BORDER_COLOR};
                border-radius: 6px;
                color: {TEXT_PRIMARY};
                font-size: 14px;  /* Increased from 13px */
                padding: 0 12px;
            }}
            ModernLineEdit:focus {{
                border: 2px solid {colors['primary']};
                background: rgba(30, 41, 59, 0.8);
            }}
            ModernLineEdit::placeholder {{
                color: {TEXT_MUTED};
                font-size: 12px;  /* Increased placeholder size */
            }}
        """)


class ModernComboBox(QComboBox):
    """Modern styled combo box"""
    
    def __init__(self, section="portscan", parent=None):
        super().__init__(parent)
        colors = SECTION_COLORS.get(section, SECTION_COLORS["portscan"])
        
        self.setFixedHeight(40)  # Increased from 38
        self.setStyleSheet(f"""
            ModernComboBox {{
                background: rgba(30, 41, 59, 0.6);
                border: 2px solid {BORDER_COLOR};
                border-radius: 6px;
                color: {TEXT_PRIMARY};
                font-size: 14px;  /* Increased from 13px */
                padding: 0 8px;
            }}
            ModernComboBox:hover {{
                border: 2px solid {colors['primary']};
            }}
            ModernComboBox::drop-down {{
                border: none;
                width: 30px;
            }}
            ModernComboBox QAbstractItemView {{
                background: rgba(30, 41, 59, 0.95);
                border: 1px solid {colors['primary']};
                color: {TEXT_PRIMARY};
                selection-background-color: {colors['primary']};
                font-size: 13px;
                padding: 4px;
            }}
        """)


class ProgressBarWidget(QProgressBar):
    """Custom progress bar"""
    
    def __init__(self, section="portscan", parent=None):
        super().__init__(parent)
        colors = SECTION_COLORS.get(section, SECTION_COLORS["portscan"])
        
        self.setStyleSheet(f"""
            ProgressBarWidget {{
                border: none;
                border-radius: 4px;
                background: rgba(30, 41, 59, 0.6);
                text-align: center;
                color: {TEXT_PRIMARY};
                font-size: 11px;
                font-weight: 600;
            }}
            ProgressBarWidget::chunk {{
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 {colors['primary']}, stop:1 {colors['secondary']});
                border-radius: 4px;
            }}
        """)


class UserDashboard(QMainWindow):
    """Main Dashboard Window"""
    
    def __init__(self, user_data=None, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Mawingu - Attack Tool")
        self.setGeometry(100, 50, 1600, 900)
        self.setStyleSheet(f"background-color: {BASE_BG};")
        
        self.current_tab = "portscan"
        self.toasts = []
        self.ping_worker = None
        self.is_flooding = False
        self.scan_worker = None
        self.is_scanning = False
        self.dns_worker = None
        self.is_dns_attacking = False
        
        self.setup_ui()
        
        if user_data:
            self.load_user_info(user_data)
    
    def setup_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        main_layout = QHBoxLayout(central_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        
        self.sidebar = self.create_sidebar()
        main_layout.addWidget(self.sidebar)
        
        self.content_stack = QStackedWidget()
        main_layout.addWidget(self.content_stack)
        
        self.create_portscan_tab()
        self.create_icmp_tab()
        self.create_dns_tab()
        self.switch_tab("portscan")
    
    def create_sidebar(self):
        sidebar = QWidget()
        sidebar.setFixedWidth(256)
        sidebar.setStyleSheet(f"""
            background: rgba(30, 41, 59, 0.6);
            border-right: 1px solid {BORDER_COLOR};
        """)
        
        layout = QVBoxLayout(sidebar)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        
        container = QWidget()
        container.setFixedHeight(120)
        container.setStyleSheet(f"border-bottom: 1px solid {BORDER_COLOR}; background: rgba(30, 41, 59, 0.4);")
        container_layout = QVBoxLayout(container)
        container_layout.setContentsMargins(16, 12, 16, 12)
        container_layout.setSpacing(6)
        container_layout.setAlignment(Qt.AlignCenter)
        
        self.avatar = AvatarWidget(70)
        container_layout.addWidget(self.avatar, alignment=Qt.AlignCenter)
        
        self.user_name_label = QLabel("Attacker")
        self.user_name_label.setStyleSheet(f"color: {TEXT_PRIMARY}; font-weight: 600; font-size: 13px;")
        self.user_name_label.setAlignment(Qt.AlignCenter)
        container_layout.addWidget(self.user_name_label)
        
        layout.addWidget(container)
        
        nav_container = QWidget()
        nav_layout = QVBoxLayout(nav_container)
        nav_layout.setContentsMargins(0, 12, 0, 12)
        nav_layout.setSpacing(4)
        
        menu_label = QLabel("MAIN MENU")
        menu_label.setStyleSheet(f"color: {TEXT_MUTED}; font-size: 10px; font-weight: 700; padding-left: 24px; margin-bottom: 6px;")
        nav_layout.addWidget(menu_label)
        
        self.nav_buttons = {}
        nav_items = [
            ("portscan", "Port Scanner", " "),
            ("icmp", "ICMP Attack", " "),
            ("dns", "DNS Attacks", " ")
        ]
        
        for tab_id, label, icon in nav_items:
            btn = SidebarButton(label, icon, tab_id)
            btn.clicked.connect(lambda checked, t=tab_id: self.switch_tab(t))
            nav_layout.addWidget(btn)
            self.nav_buttons[tab_id] = btn
        
        nav_layout.addStretch()
        layout.addWidget(nav_container)
        
        return sidebar
    
    def create_dns_tab(self):
        """Create the DNS Attacks tab with infinite attack capability"""
        section = "dns"
        colors = SECTION_COLORS[section]
        
        tab = QWidget()
        main_layout = QVBoxLayout(tab)
        main_layout.setContentsMargins(16, 16, 16, 16)
        main_layout.setSpacing(12)
        
        # Header section
        header = QLabel("DNS Attacks")
        header.setStyleSheet(f"font-size: 20px; font-weight: 700; color: {TEXT_PRIMARY};")
        header.setFixedHeight(28)
        main_layout.addWidget(header)
        
        subtitle = QLabel("DNS stress testing tool - Send DNS queries to target DNS servers")
        subtitle.setStyleSheet(f"color: {TEXT_MUTED}; font-size: 12px;")
        subtitle.setFixedHeight(18)
        main_layout.addWidget(subtitle)
        
        # Stats Cards
        stats_layout = QHBoxLayout()
        stats_layout.setSpacing(12)
        
        self.dns_sent_card = StatCardWidget("Queries Sent", " ", section)
        self.dns_sent_card.set_value(0)
        self.dns_sent_card.setFixedHeight(110)
        stats_layout.addWidget(self.dns_sent_card)
        
        self.dns_success_card = StatCardWidget("Successful", "✓", section)
        self.dns_success_card.set_value(0)
        self.dns_success_card.setFixedHeight(110)
        stats_layout.addWidget(self.dns_success_card)
        
        self.dns_failed_card = StatCardWidget("Failed/Timeout", "✗", section)
        self.dns_failed_card.set_value(0)
        self.dns_failed_card.setFixedHeight(110)
        stats_layout.addWidget(self.dns_failed_card)
        
        main_layout.addLayout(stats_layout)
        
        # Control Panel
        control_card = GlassCardWidget(section=section)
        control_card.setFixedHeight(260)
        control_layout = QVBoxLayout(control_card)
        control_layout.setContentsMargins(12, 12, 12, 12)
        control_layout.setSpacing(8)
        
        # Target DNS Server row with dropdown
        target_row = QHBoxLayout()
        target_row.setSpacing(12)
        
        target_label = QLabel("DNS Server:")
        target_label.setStyleSheet(f"color: {TEXT_SECONDARY}; font-size: 14px; font-weight: 600;")
        target_label.setFixedWidth(85)
        target_row.addWidget(target_label)
        
        # Custom input field
        self.dns_target_input = ModernLineEdit("8.8.8.8", section)
        self.dns_target_input.setFixedWidth(140)
        target_row.addWidget(self.dns_target_input)
        
        # Common DNS dropdown
        dns_dropdown_label = QLabel("Common:")
        dns_dropdown_label.setStyleSheet(f"color: {TEXT_SECONDARY}; font-size: 14px; font-weight: 600;")
        dns_dropdown_label.setFixedWidth(65)
        target_row.addWidget(dns_dropdown_label)
        
        self.dns_dropdown = ModernComboBox(section)
        self.dns_dropdown.addItems([
            "Select DNS Server...",
            "Google: 8.8.8.8",
            "Google Secondary: 8.8.4.4",
            "Cloudflare: 1.1.1.1",
            "Cloudflare Secondary: 1.0.0.1",
            "Quad9: 9.9.9.9",
            "OpenDNS: 208.67.222.222",
            "OpenDNS Secondary: 208.67.220.220",
            "Comodo: 8.26.56.26",
            "Comodo Secondary: 8.20.247.20"
        ])
        self.dns_dropdown.setFixedWidth(220)
        self.dns_dropdown.currentIndexChanged.connect(self.on_dns_dropdown_changed)
        target_row.addWidget(self.dns_dropdown, 1)
        
        target_row.addStretch()
        control_layout.addLayout(target_row)
        
        # Query Type row
        query_row = QHBoxLayout()
        query_row.setSpacing(20)
        
        query_type_label = QLabel("Query Type:")
        query_type_label.setStyleSheet(f"color: {TEXT_SECONDARY}; font-size: 14px; font-weight: 600;")
        query_type_label.setFixedWidth(90)
        query_row.addWidget(query_type_label)
        
        self.query_type_combo = ModernComboBox(section)
        self.query_type_combo.addItems([
            "A (IPv4 Address)",
            "AAAA (IPv6 Address)",
            "MX (Mail Exchange)",
            "TXT (Text Record)",
            "NS (Name Server)"
        ])
        self.query_type_combo.setFixedWidth(200)
        self.query_type_combo.setStyleSheet(self.query_type_combo.styleSheet().replace("font-size: 14px", "font-size: 13px"))
        query_row.addWidget(self.query_type_combo)
        
        query_row.addStretch()
        control_layout.addLayout(query_row)
        
        # Attack count and timeout row
        attack_timeout_row = QHBoxLayout()
        attack_timeout_row.setSpacing(30)
        
        # Left side: Attack count
        count_container = QWidget()
        count_layout = QHBoxLayout(count_container)
        count_layout.setContentsMargins(0, 0, 0, 0)
        count_layout.setSpacing(10)
        
        count_label = QLabel("Attacks:")
        count_label.setStyleSheet(f"color: {TEXT_SECONDARY}; font-size: 14px; font-weight: 600;")
        count_label.setFixedWidth(60)
        count_layout.addWidget(count_label)
        
        self.dns_count_input = ModernLineEdit("1000", section)
        self.dns_count_input.setFixedWidth(100)
        count_layout.addWidget(self.dns_count_input)
        
        self.dns_infinite_check = QCheckBox("Infinite")
        self.dns_infinite_check.setStyleSheet(f"color: {TEXT_SECONDARY}; font-size: 13px;")
        self.dns_infinite_check.toggled.connect(self.on_dns_infinite_toggled)
        count_layout.addWidget(self.dns_infinite_check)
        
        count_layout.addStretch()
        attack_timeout_row.addWidget(count_container, 2)
        
        # Right side: Timeout
        timeout_container = QWidget()
        timeout_layout = QHBoxLayout(timeout_container)
        timeout_layout.setContentsMargins(0, 0, 0, 0)
        timeout_layout.setSpacing(10)
        
        timeout_label = QLabel("Timeout:")
        timeout_label.setStyleSheet(f"color: {TEXT_SECONDARY}; font-size: 14px; font-weight: 600;")
        timeout_label.setFixedWidth(65)
        timeout_layout.addWidget(timeout_label)
        
        self.dns_timeout_input = ModernLineEdit("2", section)
        self.dns_timeout_input.setFixedWidth(60)
        timeout_layout.addWidget(self.dns_timeout_input)
        
        timeout_unit = QLabel("seconds")
        timeout_unit.setStyleSheet(f"color: {TEXT_MUTED}; font-size: 13px;")
        timeout_layout.addWidget(timeout_unit)
        
        timeout_layout.addStretch()
        attack_timeout_row.addWidget(timeout_container, 2)
        
        control_layout.addLayout(attack_timeout_row)
        
        # Buttons row
        buttons_layout = QHBoxLayout()
        buttons_layout.setSpacing(10)
        
        self.start_dns_btn = PrimaryButton("Start Attack", "▶", section)
        self.start_dns_btn.setFixedWidth(120)
        self.start_dns_btn.clicked.connect(self.start_dns_attack)
        buttons_layout.addWidget(self.start_dns_btn)
        
        self.stop_dns_btn = DangerButton("Stop Attack", "⏹")
        self.stop_dns_btn.setFixedWidth(120)
        self.stop_dns_btn.clicked.connect(self.stop_dns_attack)
        self.stop_dns_btn.setEnabled(False)
        buttons_layout.addWidget(self.stop_dns_btn)
        
        self.clear_dns_btn = SecondaryButton("Clear Terminal", " ", section)
        self.clear_dns_btn.setFixedWidth(130)
        self.clear_dns_btn.clicked.connect(self.clear_dns_terminal)
        buttons_layout.addWidget(self.clear_dns_btn)
        
        self.save_dns_results_btn = SecondaryButton("Save Results", " ", section)
        self.save_dns_results_btn.setFixedWidth(120)
        self.save_dns_results_btn.clicked.connect(self.save_dns_results)
        buttons_layout.addWidget(self.save_dns_results_btn)
        
        buttons_layout.addStretch()
        control_layout.addLayout(buttons_layout)
        
        main_layout.addWidget(control_card)
        
        # Progress bar for finite attacks
        progress_layout = QHBoxLayout()
        progress_layout.setSpacing(8)
        progress_label = QLabel("Progress:")
        progress_label.setStyleSheet(f"color: {TEXT_SECONDARY}; font-size: 13px; font-weight: 600;")
        progress_label.setFixedWidth(70)
        progress_layout.addWidget(progress_label)
        
        self.dns_progress_bar = ProgressBarWidget(section)
        self.dns_progress_bar.setFixedHeight(25)
        self.dns_progress_bar.setVisible(False)
        progress_layout.addWidget(self.dns_progress_bar, 1)
        
        self.dns_progress_label = QLabel("0%")
        self.dns_progress_label.setStyleSheet(f"color: {TEXT_SECONDARY}; font-size: 11px;")
        self.dns_progress_label.setFixedWidth(45)
        self.dns_progress_label.setVisible(False)
        progress_layout.addWidget(self.dns_progress_label)
        
        main_layout.addLayout(progress_layout)
        
        # Terminal section
        terminal_header = QHBoxLayout()
        terminal_label = QLabel("DNS Attack Terminal")
        terminal_label.setStyleSheet(f"color: {TEXT_SECONDARY}; font-size: 12px; font-weight: 600;")
        terminal_header.addWidget(terminal_label)
        terminal_header.addStretch()
        main_layout.addLayout(terminal_header)
        
        self.dns_terminal = DNSTerminal()
        self.dns_terminal.setMinimumHeight(250)
        main_layout.addWidget(self.dns_terminal, 1)
        
        self.content_stack.addWidget(tab)
        
        # Initialize stats tracking
        self.dns_sent = 0
        self.dns_successful = 0
        self.dns_failed = 0
    
    def show_common_dns_servers(self):
        """Show common DNS servers in a dialog for selection"""
        common_servers = {
            "Google DNS": "8.8.8.8",
            "Google DNS Secondary": "8.8.4.4",
            "Cloudflare DNS": "1.1.1.1",
            "Cloudflare DNS Secondary": "1.0.0.1",
            "Quad9 DNS": "9.9.9.9",
            "OpenDNS": "208.67.222.222",
            "OpenDNS Secondary": "208.67.220.220",
            "Comodo DNS": "8.26.56.26",
            "Comodo DNS Secondary": "8.20.247.20"
        }
        
        dialog = QDialog(self)
        dialog.setWindowTitle("Select Common DNS Server")
        dialog.setModal(True)
        dialog.setFixedSize(300, 400)
        dialog.setStyleSheet(f"background-color: {BASE_BG}; color: {TEXT_PRIMARY};")
        
        layout = QVBoxLayout(dialog)
        
        label = QLabel("Select a DNS server:")
        label.setStyleSheet(f"color: {TEXT_SECONDARY}; font-size: 12px; font-weight: 600; margin-bottom: 10px;")
        layout.addWidget(label)
        
        list_widget = QListWidget()
        list_widget.setStyleSheet(f"""
            QListWidget {{
                background: rgba(30, 41, 59, 0.6);
                border: 2px solid {BORDER_COLOR};
                border-radius: 6px;
                color: {TEXT_PRIMARY};
                padding: 5px;
            }}
            QListWidget::item {{
                padding: 8px;
                border-radius: 4px;
            }}
            QListWidget::item:hover {{
                background: rgba(139, 92, 246, 0.2);
            }}
            QListWidget::item:selected {{
                background: rgba(139, 92, 246, 0.4);
            }}
        """)
        
        for name, ip in common_servers.items():
            list_widget.addItem(f"{name}: {ip}")
        
        layout.addWidget(list_widget)
        
        button_layout = QHBoxLayout()
        select_btn = PrimaryButton("Select", "✓", "dns")
        select_btn.clicked.connect(lambda: self.set_dns_server_from_list(list_widget, dialog))
        button_layout.addWidget(select_btn)
        
        cancel_btn = SecondaryButton("Cancel", "✗", "dns")
        cancel_btn.clicked.connect(dialog.reject)
        button_layout.addWidget(cancel_btn)
        
        layout.addLayout(button_layout)
        
        dialog.exec_()
    
    def set_dns_server_from_list(self, list_widget, dialog):
        """Set DNS server from list selection"""
        selected = list_widget.currentItem()
        if selected:
            text = selected.text()
            # Extract IP from the string (format: "Name: IP")
            ip = text.split(": ")[-1]
            self.dns_target_input.setText(ip)
            dialog.accept()
            self.show_toast(f"DNS server set to {ip}", "success", "dns")
    
    def on_dns_infinite_toggled(self, checked):
        """Handle infinite attack toggle"""
        if checked:
            self.dns_count_input.setText("-1")
            self.dns_count_input.setEnabled(False)
            self.dns_progress_bar.setVisible(False)
            self.dns_progress_label.setVisible(False)
        else:
            self.dns_count_input.setText("1000")
            self.dns_count_input.setEnabled(True)
            self.dns_progress_bar.setVisible(True)
            self.dns_progress_label.setVisible(True)
    
    def start_dns_attack(self):
        """Start the DNS attack"""
        # Validate DNS server
        dns_server = self.dns_target_input.text().strip()
        if not dns_server:
            self.show_toast("Please enter a target DNS server IP address", "error", "dns")
            return
        
        # Validate DNS server format
        try:
            socket.inet_aton(dns_server)
        except socket.error:
            self.show_toast("Invalid DNS server IP address format", "error", "dns")
            return
        
        # Get attack count
        count_text = self.dns_count_input.text().strip()
        try:
            if count_text == "":
                attack_count = 1000
            else:
                attack_count = int(count_text)
            
            if attack_count == 0:
                attack_count = -1
            
            if attack_count < -1:
                self.show_toast("Attack count must be -1 or a positive number", "error", "dns")
                return
        except ValueError:
            self.show_toast(f"Invalid attack count: '{count_text}'", "error", "dns")
            return
        
        # Get timeout
        try:
            timeout = float(self.dns_timeout_input.text().strip())
            if timeout <= 0:
                self.show_toast("Timeout must be positive", "error", "dns")
                return
        except ValueError:
            self.show_toast("Invalid timeout value", "error", "dns")
            return
        
        # Get query type
        query_type_map = {
            "A (IPv4 Address)": "A",
            "AAAA (IPv6 Address)": "AAAA",
            "MX (Mail Exchange)": "MX",
            "TXT (Text Record)": "TXT",
            "NS (Name Server)": "NS"
        }
        query_type = query_type_map.get(self.query_type_combo.currentText(), "A")
        
        # Stop any ongoing attack
        if self.is_dns_attacking:
            self.stop_dns_attack()
        
        # Reset stats
        self.dns_sent = 0
        self.dns_successful = 0
        self.dns_failed = 0
        
        self.dns_sent_card.set_value(0)
        self.dns_success_card.set_value(0)
        self.dns_failed_card.set_value(0)
        
        # Reset progress bar for finite attacks
        if attack_count != -1:
            self.dns_progress_bar.setValue(0)
            self.dns_progress_label.setText("0%")
            self.dns_progress_bar.setVisible(True)
            self.dns_progress_label.setVisible(True)
        
        # Create and start DNS attack worker
        self.dns_worker = DNSAttackWorker(dns_server, query_type, attack_count, timeout)
        self.dns_worker.attack_update.connect(self.update_dns_stats)
        self.dns_worker.attack_response.connect(self.on_dns_response)
        self.dns_worker.attack_progress.connect(self.update_dns_progress)
        self.dns_worker.attack_started.connect(self.on_dns_attack_started)
        self.dns_worker.attack_complete.connect(self.on_dns_attack_complete)
        
        self.is_dns_attacking = True
        self.start_dns_btn.setEnabled(False)
        self.stop_dns_btn.setEnabled(True)
        
        # Disable input fields during attack
        self.dns_target_input.setEnabled(False)
        self.query_type_combo.setEnabled(False)
        self.dns_count_input.setEnabled(False if attack_count == -1 else True)
        self.dns_infinite_check.setEnabled(False)
        self.dns_timeout_input.setEnabled(False)
        
        self.dns_worker.start()
    
    def on_dns_attack_started(self, dns_server, query_type, total_attacks):
        """Handle DNS attack start event"""
        if total_attacks == -1:
            self.dns_terminal.append_system_message(f"   Starting INFINITE DNS attack on {dns_server}", "success")
            self.dns_terminal.append_system_message(f"   Query Type: {query_type}", "info")
            self.dns_terminal.append_system_message(f"   Press STOP to halt the attack", "warning")
        else:
            self.dns_terminal.append_system_message(f"   Starting DNS attack on {dns_server}", "success")
            self.dns_terminal.append_system_message(f"   Query Type: {query_type}", "info")
            self.dns_terminal.append_system_message(f"   Total Attacks: {total_attacks}", "info")
    
    def on_dns_response(self, target, response_text, query_type):
        """Handle DNS attack response"""
        self.dns_terminal.append_attack_result(target, response_text, query_type)
    
    def update_dns_stats(self, sent, success, failed):
        """Update DNS attack statistics"""
        self.dns_sent = sent
        self.dns_successful = success
        self.dns_failed = failed
        
        self.dns_sent_card.set_value(sent)
        self.dns_success_card.set_value(success)
        self.dns_failed_card.set_value(failed)
    
    def update_dns_progress(self, current, total):
        """Update DNS attack progress bar"""
        percentage = int((current / total) * 100) if total > 0 else 0
        self.dns_progress_bar.setValue(percentage)
        self.dns_progress_label.setText(f"{percentage}%")
    
    def on_dns_attack_complete(self, stats):
        """Handle DNS attack completion"""
        self.is_dns_attacking = False
        self.start_dns_btn.setEnabled(True)
        self.stop_dns_btn.setEnabled(False)
        
        # Re-enable input fields
        self.dns_target_input.setEnabled(True)
        self.query_type_combo.setEnabled(True)
        self.dns_infinite_check.setEnabled(True)
        self.dns_timeout_input.setEnabled(True)
        
        if not self.dns_infinite_check.isChecked():
            self.dns_count_input.setEnabled(True)
            self.dns_progress_bar.setVisible(True)
            self.dns_progress_label.setVisible(True)
        
        # Display completion message
        if stats["total"] == -1:
            self.dns_terminal.append_system_message("⏹️ DNS attack stopped by user", "warning")
        else:
            self.dns_terminal.append_system_message("✅ DNS attack completed successfully", "success")
            self.dns_terminal.append_system_message(f"   Total queries: {stats['sent']}", "info")
            self.dns_terminal.append_system_message(f"   Successful: {stats['successful']}", "success")
            self.dns_terminal.append_system_message(f"   Failed/Timeout: {stats['failed']}", "warning")
        
        self.show_toast(f"DNS attack completed. Sent: {stats['sent']}, Success: {stats['successful']}", "success", "dns")
        
        self.dns_worker = None
    
    def stop_dns_attack(self):
        """Stop the DNS attack"""
        if self.dns_worker and self.dns_worker.isRunning():
            self.dns_worker.stop()
            self.dns_terminal.append_system_message("⏹️ Stopping DNS attack...", "warning")
            self.show_toast("Stopping DNS attack...", "warning", "dns")
            
            # Wait a bit and then clean up
            QTimer.singleShot(1000, self.cleanup_dns_attack)
    
    def cleanup_dns_attack(self):
        """Clean up after DNS attack stop"""
        if self.dns_worker:
            self.dns_worker.quit()
            self.dns_worker.wait()
            self.dns_worker = None
        
        self.is_dns_attacking = False
        self.start_dns_btn.setEnabled(True)
        self.stop_dns_btn.setEnabled(False)
        
        # Re-enable input fields
        self.dns_target_input.setEnabled(True)
        self.query_type_combo.setEnabled(True)
        self.dns_infinite_check.setEnabled(True)
        self.dns_timeout_input.setEnabled(True)
        
        if not self.dns_infinite_check.isChecked():
            self.dns_count_input.setEnabled(True)
            self.dns_progress_bar.setVisible(True)
            self.dns_progress_label.setVisible(True)
    
    def clear_dns_terminal(self):
        """Clear the DNS terminal and reset stats"""
        # Clear terminal output
        self.dns_terminal.clear_terminal()
        
        # Reset stats variables
        self.dns_sent = 0
        self.dns_successful = 0
        self.dns_failed = 0
        
        # Reset stat cards
        self.dns_sent_card.set_value(0)
        self.dns_success_card.set_value(0)
        self.dns_failed_card.set_value(0)
        
        # Reset progress bar
        self.dns_progress_bar.setValue(0)
        self.dns_progress_label.setText("0%")
        
        self.show_toast("DNS terminal and stats cleared", "info", "dns")
    
    def save_dns_results(self):
        """Save DNS attack results to a file"""
        if self.dns_sent == 0:
            self.show_toast("No DNS attack results to save", "warning", "dns")
            return
        
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"dns_attack_results_{timestamp}.txt"
            
            with open(filename, 'w') as f:
                f.write(f"DNS Attack Results - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Target DNS Server: {self.dns_target_input.text()}\n")
                f.write(f"Query Type: {self.query_type_combo.currentText()}\n")
                f.write(f"Total Attacks: {'Infinite' if self.dns_infinite_check.isChecked() else self.dns_count_input.text()}\n")
                f.write(f"Timeout: {self.dns_timeout_input.text()} seconds\n")
                f.write(f"\nStatistics:\n")
                f.write(f"-" * 40 + "\n")
                f.write(f"Queries Sent: {self.dns_sent}\n")
                f.write(f"Successful Responses: {self.dns_successful}\n")
                f.write(f"Failed/Timeout: {self.dns_failed}\n")
                f.write(f"Success Rate: {(self.dns_successful/self.dns_sent*100):.1f}%\n" if self.dns_sent > 0 else "Success Rate: N/A\n")
            
            self.show_toast(f"Results saved to {filename}", "success", "dns")
        except Exception as e:
            self.show_toast(f"Error saving results: {str(e)}", "error", "dns")
    
    def create_portscan_tab(self):
        """Create the Port Scanner tab with full functionality"""
        section = "portscan"
        colors = SECTION_COLORS[section]
        
        tab = QWidget()
        main_layout = QVBoxLayout(tab)
        main_layout.setContentsMargins(16, 16, 16, 16)
        main_layout.setSpacing(12)
        
        # Header section
        header = QLabel("Port Scanner")
        header.setStyleSheet(f"font-size: 20px; font-weight: 700; color: {TEXT_PRIMARY};")
        header.setFixedHeight(28)
        main_layout.addWidget(header)
        
        subtitle = QLabel("Network port scanning tool - Scan for open ports on target machines")
        subtitle.setStyleSheet(f"color: {TEXT_MUTED}; font-size: 12px;")
        subtitle.setFixedHeight(18)
        main_layout.addWidget(subtitle)
        
        # Stats Cards
        stats_layout = QHBoxLayout()
        stats_layout.setSpacing(12)
        
        self.scanned_ports_card = StatCardWidget("Ports Scanned", " ", section)
        self.scanned_ports_card.set_value(0)
        self.scanned_ports_card.setFixedHeight(110)
        stats_layout.addWidget(self.scanned_ports_card)
        
        self.open_ports_card = StatCardWidget("Open Ports", " ", section)
        self.open_ports_card.set_value(0)
        self.open_ports_card.setFixedHeight(110)
        stats_layout.addWidget(self.open_ports_card)
        
        self.closed_ports_card = StatCardWidget("Closed Ports", " ", section)
        self.closed_ports_card.set_value(0)
        self.closed_ports_card.setFixedHeight(110)
        stats_layout.addWidget(self.closed_ports_card)
        
        main_layout.addLayout(stats_layout)
        
        # Control Panel
        control_card = GlassCardWidget(section=section)
        control_card.setFixedHeight(240)
        control_layout = QVBoxLayout(control_card)
        control_layout.setContentsMargins(12, 12, 12, 12)
        control_layout.setSpacing(8)
        
        # Target IP row
        target_row = QHBoxLayout()
        target_row.setSpacing(12)
        
        target_label = QLabel("Target:")
        target_label.setStyleSheet(f"color: {TEXT_SECONDARY}; font-size: 13px; font-weight: 600;")
        target_label.setFixedWidth(55)
        target_row.addWidget(target_label)
        
        self.target_ip_input = ModernLineEdit("192.168.1.1 or localhost", section)
        target_row.addWidget(self.target_ip_input, 1)
        
        # Add button to detect local IP
        detect_ip_btn = SecondaryButton("My IP", " ", section)
        detect_ip_btn.setFixedWidth(80)
        detect_ip_btn.setStyleSheet(detect_ip_btn.styleSheet().replace("font-size: 12px", "font-size: 11px"))
        detect_ip_btn.setToolTip("Detect your local IP address")
        detect_ip_btn.clicked.connect(self.detect_local_ip)
        target_row.addWidget(detect_ip_btn)
        
        control_layout.addLayout(target_row)
        
        # Port range row - REORGANIZED for better visibility
        port_row = QHBoxLayout()
        port_row.setSpacing(16)
        
        # Left side: Port inputs
        ports_container = QWidget()
        ports_layout = QHBoxLayout(ports_container)
        ports_layout.setContentsMargins(0, 0, 0, 0)
        ports_layout.setSpacing(12)
        
        # Start port
        start_port_label = QLabel("Start:")
        start_port_label.setStyleSheet(f"color: {TEXT_SECONDARY}; font-size: 13px; font-weight: 600;")
        start_port_label.setFixedWidth(45)
        ports_layout.addWidget(start_port_label)
        
        self.start_port_input = ModernLineEdit("1", section)
        self.start_port_input.setFixedWidth(90)
        ports_layout.addWidget(self.start_port_input)
        
        # End port
        end_port_label = QLabel("End:")
        end_port_label.setStyleSheet(f"color: {TEXT_SECONDARY}; font-size: 13px; font-weight: 600;")
        end_port_label.setFixedWidth(40)
        ports_layout.addWidget(end_port_label)
        
        self.end_port_input = ModernLineEdit("1000", section)
        self.end_port_input.setFixedWidth(90)
        ports_layout.addWidget(self.end_port_input)
        
        ports_layout.addStretch()
        port_row.addWidget(ports_container, 2)
        
        # Right side: Presets
        presets_container = QWidget()
        presets_layout = QHBoxLayout(presets_container)
        presets_layout.setContentsMargins(0, 0, 0, 0)
        presets_layout.setSpacing(8)
        
        preset_label = QLabel("Presets:")
        preset_label.setStyleSheet(f"color: {TEXT_SECONDARY}; font-size: 13px; font-weight: 600;")
        presets_layout.addWidget(preset_label)
        
        common_ports_btn = SecondaryButton("Common", " ", section)
        common_ports_btn.setFixedWidth(90)
        common_ports_btn.setStyleSheet(common_ports_btn.styleSheet().replace("font-size: 12px", "font-size: 11px"))
        self.set_custom_tooltip(common_ports_btn, "COMMON PORTS", "Scan well-known ports 1-1024", "portscan")
        common_ports_btn.clicked.connect(lambda: self.set_port_preset("common"))
        presets_layout.addWidget(common_ports_btn)
        
        all_ports_btn = SecondaryButton("All", " ", section)
        all_ports_btn.setFixedWidth(60)
        all_ports_btn.setStyleSheet(all_ports_btn.styleSheet().replace("font-size: 12px", "font-size: 11px"))
        self.set_custom_tooltip(all_ports_btn, "ALL PORTS", "Scan all ports 1-65535", "portscan")
        all_ports_btn.clicked.connect(lambda: self.set_port_preset("all"))
        presets_layout.addWidget(all_ports_btn)
        
        web_ports_btn = SecondaryButton("Web", " ", section)
        web_ports_btn.setFixedWidth(60)
        web_ports_btn.setStyleSheet(web_ports_btn.styleSheet().replace("font-size: 12px", "font-size: 11px"))
        self.set_custom_tooltip(web_ports_btn, "WEB PORTS", "80, 443, 8080", "portscan")
        web_ports_btn.clicked.connect(lambda: self.set_port_preset("web"))
        presets_layout.addWidget(web_ports_btn)
        
        port_row.addWidget(presets_container, 3)
        control_layout.addLayout(port_row)
        
        # Scan options row - REORGANIZED for better spacing
        options_row = QHBoxLayout()
        options_row.setSpacing(20)
        
        # Scan type - wider and more visible
        scan_type_widget = QWidget()
        scan_type_layout = QHBoxLayout(scan_type_widget)
        scan_type_layout.setContentsMargins(0, 0, 0, 0)
        scan_type_layout.setSpacing(8)
        
        scan_type_label = QLabel("Type:")
        scan_type_label.setStyleSheet(f"color: {TEXT_SECONDARY}; font-size: 13px; font-weight: 600;")
        scan_type_label.setFixedWidth(40)
        scan_type_layout.addWidget(scan_type_label)
        
        self.scan_type_combo = ModernComboBox(section)
        self.scan_type_combo.addItems(["TCP Connect", "SYN Scan (Admin)"])
        self.scan_type_combo.setFixedWidth(180)
        self.scan_type_combo.setStyleSheet(self.scan_type_combo.styleSheet().replace("font-size: 13px", "font-size: 12px"))
        scan_type_layout.addWidget(self.scan_type_combo)
        scan_type_layout.addStretch()
        options_row.addWidget(scan_type_widget, 3)
        
        # Timeout
        timeout_widget = QWidget()
        timeout_layout = QHBoxLayout(timeout_widget)
        timeout_layout.setContentsMargins(0, 0, 0, 0)
        timeout_layout.setSpacing(6)
        
        timeout_label = QLabel("Timeout:")
        timeout_label.setStyleSheet(f"color: {TEXT_SECONDARY}; font-size: 13px; font-weight: 600;")
        timeout_label.setFixedWidth(55)
        timeout_layout.addWidget(timeout_label)
        
        self.timeout_input = ModernLineEdit("2", section)
        self.timeout_input.setFixedWidth(55)
        timeout_layout.addWidget(self.timeout_input)
        
        timeout_unit = QLabel("s")
        timeout_unit.setStyleSheet(f"color: {TEXT_MUTED}; font-size: 12px;")
        timeout_layout.addWidget(timeout_unit)
        timeout_layout.addStretch()
        options_row.addWidget(timeout_widget, 1)
        
        # Thread count
        threads_widget = QWidget()
        threads_layout = QHBoxLayout(threads_widget)
        threads_layout.setContentsMargins(0, 0, 0, 0)
        threads_layout.setSpacing(6)
        
        threads_label = QLabel("Threads:")
        threads_label.setStyleSheet(f"color: {TEXT_SECONDARY}; font-size: 13px; font-weight: 600;")
        threads_label.setFixedWidth(55)
        threads_layout.addWidget(threads_label)
        
        self.threads_input = ModernLineEdit("100", section)
        self.threads_input.setFixedWidth(70)
        threads_layout.addWidget(self.threads_input)
        threads_layout.addStretch()
        options_row.addWidget(threads_widget, 1)
        
        control_layout.addLayout(options_row)
        
        # Progress bar
        progress_layout = QHBoxLayout()
        progress_layout.setSpacing(8)
        progress_label = QLabel("Progress:")
        progress_label.setStyleSheet(f"color: {TEXT_SECONDARY}; font-size: 12px; font-weight: 600;")
        progress_label.setFixedWidth(65)
        progress_layout.addWidget(progress_label)
        
        self.scan_progress_bar = ProgressBarWidget(section)
        self.scan_progress_bar.setFixedHeight(25)
        progress_layout.addWidget(self.scan_progress_bar, 1)
        
        self.progress_label = QLabel("0%")
        self.progress_label.setStyleSheet(f"color: {TEXT_SECONDARY}; font-size: 11px;")
        self.progress_label.setFixedWidth(45)
        progress_layout.addWidget(self.progress_label)
        
        control_layout.addLayout(progress_layout)
        
        # Buttons row
        buttons_layout = QHBoxLayout()
        buttons_layout.setSpacing(10)
        
        self.start_scan_btn = PrimaryButton("Start Scan", "▶", section)
        self.start_scan_btn.setFixedWidth(120)
        self.start_scan_btn.clicked.connect(self.start_port_scan)
        buttons_layout.addWidget(self.start_scan_btn)
        
        self.stop_scan_btn = DangerButton("Stop Scan", "⏹")
        self.stop_scan_btn.setFixedWidth(120)
        self.stop_scan_btn.clicked.connect(self.stop_port_scan)
        self.stop_scan_btn.setEnabled(False)
        buttons_layout.addWidget(self.stop_scan_btn)
        
        self.clear_scan_btn = SecondaryButton("Clear Results", " ", section)
        self.clear_scan_btn.setFixedWidth(130)
        self.clear_scan_btn.clicked.connect(self.clear_scan_results)
        buttons_layout.addWidget(self.clear_scan_btn)
        
        self.save_results_btn = SecondaryButton("Save Results", " ", section)
        self.save_results_btn.setFixedWidth(120)
        self.save_results_btn.clicked.connect(self.save_scan_results)
        buttons_layout.addWidget(self.save_results_btn)
        
        buttons_layout.addStretch()
        control_layout.addLayout(buttons_layout)
        
        main_layout.addWidget(control_card)
        
        # Terminal section
        terminal_header = QHBoxLayout()
        terminal_label = QLabel("Scan Results Terminal")
        terminal_label.setStyleSheet(f"color: {TEXT_SECONDARY}; font-size: 12px; font-weight: 600;")
        terminal_header.addWidget(terminal_label)
        terminal_header.addStretch()
        main_layout.addLayout(terminal_header)
        
        self.scan_terminal = PortScanTerminal()
        self.scan_terminal.setMinimumHeight(250)
        main_layout.addWidget(self.scan_terminal, 1)
        
        self.content_stack.addWidget(tab)
        
        # Initialize stats tracking
        self.scanned_ports = 0
        self.open_ports_count = 0
        self.closed_ports_count = 0
        self.open_ports_list = []
    
    def create_icmp_tab(self):
        """Create the ICMP Attack tab with working ping flooding - RESIZED for 1600x900"""
        section = "icmp"
        colors = SECTION_COLORS[section]
        
        tab = QWidget()
        main_layout = QVBoxLayout(tab)
        main_layout.setContentsMargins(16, 16, 16, 16)
        main_layout.setSpacing(12)
        
        # Header section - Compact
        header = QLabel("ICMP Attack")
        header.setStyleSheet(f"font-size: 20px; font-weight: 700; color: {TEXT_PRIMARY};")
        header.setFixedHeight(28)
        main_layout.addWidget(header)
        
        subtitle = QLabel("Ping flooding tool - Send REAL ICMP packets to target(s)")
        subtitle.setStyleSheet(f"color: {TEXT_MUTED}; font-size: 12px;")
        subtitle.setFixedHeight(18)
        main_layout.addWidget(subtitle)
        
        # Stats Cards - Horizontal layout, compact height
        stats_layout = QHBoxLayout()
        stats_layout.setSpacing(12)
        
        self.sent_card = StatCardWidget("Pings Sent", " ", section)
        self.sent_card.set_value(0)
        self.sent_card.setFixedHeight(110)
        stats_layout.addWidget(self.sent_card)
        
        self.success_card = StatCardWidget("Successful", "✓", section)
        self.success_card.set_value(0)
        self.success_card.setFixedHeight(110)
        stats_layout.addWidget(self.success_card)
        
        self.failed_card = StatCardWidget("Failed", "✗", section)
        self.failed_card.set_value(0)
        self.failed_card.setFixedHeight(110)
        stats_layout.addWidget(self.failed_card)
        
        main_layout.addLayout(stats_layout)
        
        # Control Panel - Compact layout
        control_card = GlassCardWidget(section=section)
        control_card.setFixedHeight(160)
        control_layout = QVBoxLayout(control_card)
        control_layout.setContentsMargins(12, 12, 12, 12)
        control_layout.setSpacing(8)
        
        # Target input row
        target_row = QHBoxLayout()
        target_row.setSpacing(8)
        
        target_label = QLabel("Target(s) (IP or Domain):")
        target_label.setStyleSheet(f"color: {TEXT_SECONDARY}; font-size: 12px; font-weight: 600;")
        target_label.setFixedWidth(140)
        target_row.addWidget(target_label)
        
        self.target_input = ModernLineEdit("e.g., 8.8.8.8, google.com, 192.168.1.1", section)
        target_row.addWidget(self.target_input)
        
        help_label = QLabel("Separate multiple targets with commas")
        help_label.setStyleSheet(f"color: {TEXT_MUTED}; font-size: 10px;")
        help_label.setFixedWidth(180)
        target_row.addWidget(help_label)
        
        control_layout.addLayout(target_row)
        
        # Options row - Count, Interval, Infinite checkbox
        options_row = QHBoxLayout()
        options_row.setSpacing(12)
        
        # Count
        count_widget = QWidget()
        count_layout = QHBoxLayout(count_widget)
        count_layout.setContentsMargins(0, 0, 0, 0)
        count_layout.setSpacing(6)
        count_label = QLabel("Count:")
        count_label.setStyleSheet(f"color: {TEXT_SECONDARY}; font-size: 12px; font-weight: 600;")
        count_label.setFixedWidth(45)
        count_layout.addWidget(count_label)
        
        self.count_input = ModernLineEdit("1000", section)
        self.count_input.setFixedWidth(80)
        count_layout.addWidget(self.count_input)
        
        self.infinite_check = QCheckBox("Infinite")
        self.infinite_check.setStyleSheet(f"color: {TEXT_SECONDARY}; font-size: 12px;")
        self.infinite_check.toggled.connect(self.on_infinite_toggled)
        count_layout.addWidget(self.infinite_check)
        count_layout.addStretch()
        options_row.addWidget(count_widget, 1)
        
        # Interval
        interval_widget = QWidget()
        interval_layout = QHBoxLayout(interval_widget)
        interval_layout.setContentsMargins(0, 0, 0, 0)
        interval_layout.setSpacing(6)
        interval_label = QLabel("Interval (s):")
        interval_label.setStyleSheet(f"color: {TEXT_SECONDARY}; font-size: 12px; font-weight: 600;")
        interval_label.setFixedWidth(70)
        interval_layout.addWidget(interval_label)
        
        self.interval_input = ModernLineEdit("0.1", section)
        self.interval_input.setFixedWidth(60)
        interval_layout.addWidget(self.interval_input)
        
        interval_hint = QLabel("0.1s = 10 pings/sec")
        interval_hint.setStyleSheet(f"color: {TEXT_MUTED}; font-size: 10px;")
        interval_layout.addWidget(interval_hint)
        interval_layout.addStretch()
        options_row.addWidget(interval_widget, 1)
        
        control_layout.addLayout(options_row)
        
        # Buttons row
        buttons_layout = QHBoxLayout()
        buttons_layout.setSpacing(10)
        
        self.start_flood_btn = PrimaryButton("Start Flood", "▶", section)
        self.start_flood_btn.setFixedWidth(120)
        self.start_flood_btn.clicked.connect(self.start_ping_flood)
        buttons_layout.addWidget(self.start_flood_btn)
        
        self.stop_flood_btn = DangerButton("Stop Flood", "⏹")
        self.stop_flood_btn.setFixedWidth(120)
        self.stop_flood_btn.clicked.connect(self.stop_ping_flood)
        self.stop_flood_btn.setEnabled(False)
        buttons_layout.addWidget(self.stop_flood_btn)
        
        self.clear_terminal_btn = SecondaryButton("Clear Terminal", " ", section)
        self.clear_terminal_btn.setFixedWidth(130)
        self.clear_terminal_btn.clicked.connect(self.clear_terminal)
        buttons_layout.addWidget(self.clear_terminal_btn)
        
        buttons_layout.addStretch()
        control_layout.addLayout(buttons_layout)
        
        main_layout.addWidget(control_card)
        
        # Terminal section - Takes remaining space
        terminal_header = QHBoxLayout()
        terminal_label = QLabel("Ping Output Terminal")
        terminal_label.setStyleSheet(f"color: {TEXT_SECONDARY}; font-size: 12px; font-weight: 600;")
        terminal_header.addWidget(terminal_label)
        terminal_header.addStretch()
        main_layout.addLayout(terminal_header)
        
        self.terminal = TerminalTextEdit(section)
        self.terminal.setMinimumHeight(200)
        main_layout.addWidget(self.terminal, 1)  # Stretch factor 1 to fill remaining space
        
        self.content_stack.addWidget(tab)
    
    def detect_local_ip(self):
        """Detect and set the local IP address"""
        try:
            # Create a socket to get local IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            
            self.target_ip_input.setText(local_ip)
            self.show_toast(f"Local IP detected: {local_ip}", "success", "portscan")
        except Exception as e:
            self.show_toast(f"Could not detect local IP: {str(e)}", "error", "portscan")
    
    def set_port_preset(self, preset_type):
        """Set port range based on preset"""
        if preset_type == "common":
            self.start_port_input.setText("1")
            self.end_port_input.setText("1024")
            self.show_toast("Set to common ports (1-1024)", "info", "portscan")
        elif preset_type == "all":
            self.start_port_input.setText("1")
            self.end_port_input.setText("65535")
            self.show_toast("Set to all ports (1-65535)", "info", "portscan")
        elif preset_type == "web":
            self.start_port_input.setText("80")
            self.end_port_input.setText("8080")
            self.show_toast("Set to web ports (80-8080)", "info", "portscan")
    
    def start_port_scan(self):
        """Start the port scan"""
        # Validate target IP
        target_ip = self.target_ip_input.text().strip()
        if not target_ip:
            self.show_toast("Please enter a target IP address", "error", "portscan")
            return
        
        # Resolve localhost if needed
        if target_ip.lower() == "localhost":
            target_ip = "127.0.0.1"
        
        # Validate port range
        try:
            start_port = int(self.start_port_input.text().strip())
            end_port = int(self.end_port_input.text().strip())
            
            if start_port < 1 or start_port > 65535:
                self.show_toast("Start port must be between 1 and 65535", "error", "portscan")
                return
            
            if end_port < 1 or end_port > 65535:
                self.show_toast("End port must be between 1 and 65535", "error", "portscan")
                return
            
            if start_port > end_port:
                self.show_toast("Start port must be less than or equal to end port", "error", "portscan")
                return
                
        except ValueError:
            self.show_toast("Invalid port number", "error", "portscan")
            return
        
        # Validate timeout
        try:
            timeout = float(self.timeout_input.text().strip())
            if timeout <= 0:
                self.show_toast("Timeout must be positive", "error", "portscan")
                return
        except ValueError:
            self.show_toast("Invalid timeout value", "error", "portscan")
            return
        
        # Validate threads
        try:
            threads = int(self.threads_input.text().strip())
            if threads <= 0:
                self.show_toast("Threads must be positive", "error", "portscan")
                return
        except ValueError:
            self.show_toast("Invalid threads value", "error", "portscan")
            return
        
        # Determine scan type
        scan_type = "connect" if self.scan_type_combo.currentIndex() == 0 else "syn"
        
        # Stop any ongoing scan
        if self.is_scanning:
            self.stop_port_scan()
        
        # Reset stats
        self.scanned_ports = 0
        self.open_ports_count = 0
        self.closed_ports_count = 0
        self.open_ports_list = []
        
        self.scanned_ports_card.set_value(0)
        self.open_ports_card.set_value(0)
        self.closed_ports_card.set_value(0)
        
        # Create and start scan worker
        self.scan_worker = PortScanWorker(target_ip, start_port, end_port, scan_type, timeout, threads)
        self.scan_worker.port_update.connect(self.on_port_result)
        self.scan_worker.scan_progress.connect(self.update_scan_progress)
        self.scan_worker.scan_complete.connect(self.on_scan_complete)
        self.scan_worker.scan_started.connect(self.on_scan_started)
        
        self.is_scanning = True
        self.start_scan_btn.setEnabled(False)
        self.stop_scan_btn.setEnabled(True)
        
        # Disable input fields during scan
        self.target_ip_input.setEnabled(False)
        self.start_port_input.setEnabled(False)
        self.end_port_input.setEnabled(False)
        self.scan_type_combo.setEnabled(False)
        self.timeout_input.setEnabled(False)
        self.threads_input.setEnabled(False)
        
        self.scan_worker.start()
        
        self.show_toast(f"Starting port scan on {target_ip}", "success", "portscan")
    
    def on_scan_started(self, target_ip, start_port, end_port):
        """Handle scan start event"""
        self.scan_terminal.append_system_message(f"Starting port scan on {target_ip}", "info")
        self.scan_terminal.append_system_message(f"Port range: {start_port} - {end_port}", "info")
        self.scan_terminal.append_system_message(f"Scan type: {self.scan_type_combo.currentText()}", "info")
    
    def on_port_result(self, port, status, service):
        """Handle individual port scan result"""
        self.scanned_ports += 1
        self.scanned_ports_card.set_value(self.scanned_ports)
        
        if status == 1:  # Open
            self.open_ports_count += 1
            self.open_ports_card.set_value(self.open_ports_count)
            self.open_ports_list.append(port)
            self.scan_terminal.append_scan_result(port, status, service)
        elif status == 0:  # Closed
            self.closed_ports_count += 1
            self.closed_ports_card.set_value(self.closed_ports_count)
        elif status == 2:  # Warning
            self.scan_terminal.append_scan_result(port, status, service)
    
    def update_scan_progress(self, current, total):
        """Update scan progress bar"""
        percentage = int((current / total) * 100) if total > 0 else 0
        self.scan_progress_bar.setValue(percentage)
        self.progress_label.setText(f"{percentage}%")
    
    def on_scan_complete(self, open_ports):
        """Handle scan completion"""
        self.is_scanning = False
        self.start_scan_btn.setEnabled(True)
        self.stop_scan_btn.setEnabled(False)
        
        # Re-enable input fields
        self.target_ip_input.setEnabled(True)
        self.start_port_input.setEnabled(True)
        self.end_port_input.setEnabled(True)
        self.scan_type_combo.setEnabled(True)
        self.timeout_input.setEnabled(True)
        self.threads_input.setEnabled(True)
        
        # Display summary
        self.scan_terminal.append_system_message("✅ Port scan completed", "success")
        
        if open_ports:
            self.scan_terminal.append_system_message(f"Found {len(open_ports)} open port(s): {', '.join(map(str, open_ports))}", "info")
        else:
            self.scan_terminal.append_system_message("No open ports found in the specified range", "warning")
        
        self.show_toast(f"Scan completed. Found {len(open_ports)} open port(s)", "success", "portscan")
    
    def stop_port_scan(self):
        """Stop the port scan"""
        if self.scan_worker and self.scan_worker.isRunning():
            self.scan_worker.stop()
            self.scan_terminal.append_system_message("Stopping port scan...", "warning")
            self.show_toast("Stopping port scan...", "warning", "portscan")
            
            # Wait a bit and then clean up
            QTimer.singleShot(1000, self.cleanup_scan)
    
    def cleanup_scan(self):
        """Clean up after scan stop"""
        if self.scan_worker:
            self.scan_worker.quit()
            self.scan_worker.wait()
            self.scan_worker = None
        
        self.is_scanning = False
        self.start_scan_btn.setEnabled(True)
        self.stop_scan_btn.setEnabled(False)
        
        # Re-enable input fields
        self.target_ip_input.setEnabled(True)
        self.start_port_input.setEnabled(True)
        self.end_port_input.setEnabled(True)
        self.scan_type_combo.setEnabled(True)
        self.timeout_input.setEnabled(True)
        self.threads_input.setEnabled(True)
    
    def clear_scan_results(self):
        """Clear scan results and reset stats"""
        self.scanned_ports = 0
        self.open_ports_count = 0
        self.closed_ports_count = 0
        self.open_ports_list = []
        
        self.scanned_ports_card.set_value(0)
        self.open_ports_card.set_value(0)
        self.closed_ports_card.set_value(0)
        self.scan_progress_bar.setValue(0)
        self.progress_label.setText("0%")
        
        self.scan_terminal.clear_terminal()
        self.show_toast("Scan results cleared", "info", "portscan")
    
    def save_scan_results(self):
        """Save scan results to a file"""
        if not self.open_ports_list:
            self.show_toast("No scan results to save", "warning", "portscan")
            return
        
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"port_scan_results_{timestamp}.txt"
            
            with open(filename, 'w') as f:
                f.write(f"Port Scan Results - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Target: {self.target_ip_input.text()}\n")
                f.write(f"Port Range: {self.start_port_input.text()} - {self.end_port_input.text()}\n")
                f.write(f"Scan Type: {self.scan_type_combo.currentText()}\n")
                f.write(f"Total Ports Scanned: {self.scanned_ports}\n")
                f.write(f"Open Ports Found: {len(self.open_ports_list)}\n")
                f.write(f"Closed Ports: {self.closed_ports_count}\n")
                f.write("\nOpen Ports:\n")
                f.write("-" * 40 + "\n")
                for port in self.open_ports_list:
                    f.write(f"Port {port}\n")
            
            self.show_toast(f"Results saved to {filename}", "success", "portscan")
        except Exception as e:
            self.show_toast(f"Error saving results: {str(e)}", "error", "portscan")
    
    def on_infinite_toggled(self, checked):
        if checked:
            self.count_input.setText("-1")
            self.count_input.setEnabled(False)
        else:
            self.count_input.setText("1000")
            self.count_input.setEnabled(True)
    
    def start_ping_flood(self):
        """Start the ping flood attack"""
        targets_text = self.target_input.text().strip()
        if not targets_text:
            self.show_toast("Please enter at least one target", "error", "icmp")
            return
        
        targets = [t.strip() for t in targets_text.split(',') if t.strip()]
        if not targets:
            self.show_toast("Please enter valid target(s)", "error", "icmp")
            return
        
        count_text = self.count_input.text().strip()
        try:
            if count_text == "":
                ping_count = 1000
            else:
                ping_count = int(count_text)
            
            if ping_count == 0:
                ping_count = -1
            
            if ping_count < -1:
                self.show_toast("Ping count must be -1 or a positive number", "error", "icmp")
                return
        except ValueError:
            self.show_toast(f"Invalid ping count: '{count_text}'", "error", "icmp")
            return
        
        try:
            interval = float(self.interval_input.text().strip())
            if interval < 0:
                self.show_toast("Interval cannot be negative", "error", "icmp")
                return
            if interval < 0.05:
                interval = 0.05
                self.interval_input.setText("0.05")
        except ValueError:
            self.show_toast("Invalid interval value", "error", "icmp")
            return
        
        if self.is_flooding:
            self.stop_ping_flood()
        
        self.ping_worker = PingWorker(targets, ping_count, interval)
        self.ping_worker.ping_update.connect(self.update_stats)
        self.ping_worker.ping_reply.connect(self.on_ping_reply)
        self.ping_worker.finished.connect(self.on_flood_finished)
        
        self.is_flooding = True
        self.start_flood_btn.setEnabled(False)
        self.stop_flood_btn.setEnabled(True)
        
        self.target_input.setEnabled(False)
        self.count_input.setEnabled(False)
        self.interval_input.setEnabled(False)
        self.infinite_check.setEnabled(False)
        
        self.sent_card.set_value(0)
        self.success_card.set_value(0)
        self.failed_card.set_value(0)
        
        self.ping_worker.start()
        
        count_msg = "INFINITE" if ping_count == -1 else f"{ping_count * len(targets)}"
        target_list = ", ".join(targets)
        self.terminal.append_system_message(f"   Starting REAL Ping Flood Attack", "success")
        self.terminal.append_system_message(f"   Targets: {target_list}", "info")
        self.terminal.append_system_message(f"   Total pings: {count_msg}", "info")
        self.terminal.append_system_message(f"   Interval: {interval}s ({int(1/interval)} pings/sec)", "info")
        self.terminal.append_system_message(f"   Press STOP to halt", "warning")
        
        self.show_toast(f"Ping flood started on {len(targets)} target(s)", "success", "icmp")
    
    def stop_ping_flood(self):
        if self.ping_worker and self.ping_worker.isRunning():
            self.ping_worker.stop()
            self.terminal.append_system_message("⏹️ Stopping ping flood...", "warning")
            self.show_toast("Stopping ping flood...", "warning", "icmp")
    
    def on_flood_finished(self):
        self.is_flooding = False
        self.start_flood_btn.setEnabled(True)
        self.stop_flood_btn.setEnabled(False)
        
        self.target_input.setEnabled(True)
        self.count_input.setEnabled(True)
        self.interval_input.setEnabled(True)
        self.infinite_check.setEnabled(True)
        
        if self.ping_worker:
            self.terminal.append_system_message("✅ Ping flood completed", "success")
            self.show_toast("Ping flood completed", "success", "icmp")
        
        self.ping_worker = None
    
    def on_ping_reply(self, target, reply_text):
        self.terminal.append_ping_result(target, reply_text)
    
    def update_stats(self, sent, success, failed):
        self.sent_card.set_value(sent)
        self.success_card.set_value(success)
        self.failed_card.set_value(failed)
    
    def clear_terminal(self):
        """Clear the ICMP terminal and reset stats"""
        # Clear terminal output
        self.terminal.clear_terminal()
        
        # Reset stat cards to 0
        self.sent_card.set_value(0)
        self.success_card.set_value(0)
        self.failed_card.set_value(0)
        
        self.show_toast("Terminal and stats cleared", "info", "icmp")
    
    def switch_tab(self, tab_name):
        self.current_tab = tab_name
        for name, btn in self.nav_buttons.items():
            btn.update_style(name == tab_name)
        tab_index = ["portscan", "icmp", "dns"].index(tab_name)
        self.content_stack.setCurrentIndex(tab_index)
        
    def on_dns_dropdown_changed(self, index):
        """Handle DNS dropdown selection"""
        if index == 0:  # "Select DNS Server..."
            return
        
        # Extract IP from dropdown text (format: "Name: IP")
        text = self.dns_dropdown.currentText()
        try:
            ip = text.split(": ")[1]
            self.dns_target_input.setText(ip)
            self.show_toast(f"DNS server set to {ip}", "success", "dns")
        except IndexError:
            pass
        
    def set_custom_tooltip(self, widget, title, content, section="portscan"):
        """Set a custom-styled tooltip with section colors"""
        colors = SECTION_COLORS.get(section, SECTION_COLORS["portscan"])
        
        # HTML formatted tooltip with inline styling
        tooltip_html = f"""
        <div style='background-color: #1e293b; 
                    color: {TEXT_PRIMARY}; 
                    padding: 8px 12px; 
                    border: 2px solid {colors["primary"]}; 
                    border-radius: 6px;
                    font-size: 13px;
                    font-family: Segoe UI, sans-serif;'>
            <span style='color: {colors["light"]}; font-weight: bold; font-size: 12px;'>{title}</span><br>
            <span style='color: {TEXT_PRIMARY};'>{content}</span>
        </div>
        """
        widget.setToolTip(tooltip_html)
    
    def show_toast(self, message, type_="success", section=None):
        if section is None:
            section = self.current_tab if self.current_tab in SECTION_COLORS else "portscan"
        
        toast = ToastNotification(message, type_, self, section)
        toast.adjustSize()
        x = self.width() - toast.width() - 20
        y = self.height() - toast.height() - 20 - (len(self.toasts) * 50)
        toast.move(x, y)
        toast.show()
        self.toasts.append(toast)
        QTimer.singleShot(3000, lambda: self.hide_toast(toast))
    
    def hide_toast(self, toast):
        toast.hide()
        if toast in self.toasts:
            self.toasts.remove(toast)
            for i, t in enumerate(self.toasts):
                x = self.width() - t.width() - 20
                y = self.height() - t.height() - 20 - (i * 50)
                t.move(x, y)
    
    def load_user_info(self, user_data):
        self.user_name_label.setText("Attacker")
        self.show_toast("Welcome, Attacker!", "success", "portscan")


def main():
    app = QApplication(sys.argv)
    font = QFont("Segoe UI", 10)
    app.setFont(font)
    app.setStyle("Fusion")
    dashboard = UserDashboard()
    dashboard.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
