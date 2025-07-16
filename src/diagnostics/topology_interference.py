"""
Topology and Interference Diagnostics Module for SuperSleuth Network

This module provides comprehensive diagnostics for WiFi placement issues,
interference detection, network topology discovery, and signal quality analysis.
"""

import subprocess
import re
import json
import time
import platform
import socket
import struct
from typing import Dict, List, Tuple, Optional, Set
from dataclasses import dataclass, field
from collections import defaultdict
from datetime import datetime
import math


@dataclass
class AccessPoint:
    """Represents a wireless access point"""
    ssid: str
    bssid: str
    channel: int
    frequency: float
    signal_strength: int  # dBm
    security: str
    bandwidth: int = 20  # MHz
    capabilities: List[str] = field(default_factory=list)
    last_seen: datetime = field(default_factory=datetime.now)
    
    @property
    def channel_width(self) -> List[int]:
        """Get the channels affected by this AP based on bandwidth"""
        if self.bandwidth == 20:
            return [self.channel]
        elif self.bandwidth == 40:
            # 40MHz uses primary + adjacent channel
            if self.channel <= 7:
                return [self.channel, self.channel + 4]
            else:
                return [self.channel - 4, self.channel]
        elif self.bandwidth == 80:
            # 80MHz uses 4 channels
            base = ((self.channel - 1) // 4) * 4 + 1
            return list(range(base, base + 4))
        return [self.channel]


@dataclass
class NetworkNode:
    """Represents a network device (router, switch, etc.)"""
    ip_address: str
    mac_address: str
    hostname: str
    device_type: str
    connected_devices: List[str] = field(default_factory=list)
    latency: float = 0.0
    hop_count: int = 0


@dataclass
class SignalQuality:
    """Signal quality metrics"""
    snr: float  # Signal-to-Noise Ratio in dB
    noise_floor: float  # dBm
    tx_rate: float  # Mbps
    rx_rate: float  # Mbps
    retry_rate: float  # percentage
    error_rate: float  # percentage
    mcs_index: int  # Modulation and Coding Scheme


class TopologyInterferenceDiagnostics:
    """Main diagnostics class for topology and interference analysis"""
    
    def __init__(self):
        self.system = platform.system()
        self.access_points: Dict[str, AccessPoint] = {}
        self.network_topology: Dict[str, NetworkNode] = {}
        self.interference_map: Dict[int, List[AccessPoint]] = defaultdict(list)
        self.signal_history: List[Dict] = []
        
    def scan_wifi_networks(self) -> Dict[str, AccessPoint]:
        """Scan for available WiFi networks"""
        if self.system == "Darwin":  # macOS
            return self._scan_wifi_macos()
        elif self.system == "Linux":
            return self._scan_wifi_linux()
        elif self.system == "Windows":
            return self._scan_wifi_windows()
        else:
            raise NotImplementedError(f"WiFi scanning not implemented for {self.system}")
    
    def _scan_wifi_macos(self) -> Dict[str, AccessPoint]:
        """Scan WiFi networks on macOS"""
        try:
            # Get WiFi interface
            cmd = ["networksetup", "-listallhardwareports"]
            result = subprocess.run(cmd, capture_output=True, text=True)
            wifi_interface = None
            
            lines = result.stdout.split('\n')
            for i, line in enumerate(lines):
                if "Wi-Fi" in line and i + 1 < len(lines):
                    device_line = lines[i + 1]
                    if "Device:" in device_line:
                        wifi_interface = device_line.split("Device:")[1].strip()
                        break
            
            if not wifi_interface:
                return {}
            
            # Scan networks - try different approaches
            aps = {}
            
            # Method 1: Try airport scan with BSSID
            cmd = [
                "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport",
                wifi_interface,
                "-s"
            ]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0 and result.stdout:
                aps = self._parse_airport_output(result.stdout)
            
            # If no results, try without interface name
            if not aps:
                cmd = [
                    "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport",
                    "-s"
                ]
                result = subprocess.run(cmd, capture_output=True, text=True)
                
                if result.returncode == 0 and result.stdout:
                    aps = self._parse_airport_output(result.stdout)
            
            # Method 2: If still no results, try system_profiler as fallback
            if not aps:
                cmd = ["system_profiler", "SPAirPortDataType", "-json"]
                result = subprocess.run(cmd, capture_output=True, text=True)
                
                if result.returncode == 0:
                    try:
                        import json
                        data = json.loads(result.stdout)
                        # Parse system_profiler output
                        # This is a fallback method with limited info
                    except:
                        pass
            
            return aps
            
        except Exception as e:
            print(f"Error scanning WiFi on macOS: {e}")
            return {}
    
    def _parse_airport_output(self, output: str) -> Dict[str, AccessPoint]:
        """Parse airport command output"""
        aps = {}
        
        # Skip header line
        lines = output.strip().split('\n')[1:]
        
        for line in lines:
            if not line.strip():
                continue
            
            try:
                # First, try to extract numeric values which are more reliable
                # Look for patterns like "-92  4" (RSSI and channel)
                import re
                
                # Find all sequences of numbers that could be RSSI and channel
                numbers = re.findall(r'-?\d+', line)
                
                if len(numbers) < 2:
                    continue
                
                # Find RSSI (negative number between -100 and -30)
                rssi = None
                rssi_index = -1
                for i, num in enumerate(numbers):
                    n = int(num)
                    if -100 <= n <= -30:
                        rssi = n
                        rssi_index = i
                        break
                
                if rssi is None:
                    continue
                
                # Channel is usually the next number after RSSI
                if rssi_index + 1 < len(numbers):
                    channel_str = numbers[rssi_index + 1]
                    channel = int(channel_str)
                else:
                    continue
                
                # Extract SSID - it's everything before the RSSI number
                rssi_pos = line.find(str(rssi))
                if rssi_pos > 0:
                    ssid = line[:rssi_pos].strip()
                else:
                    ssid = "Unknown"
                
                # Generate a pseudo-BSSID based on SSID and channel
                # This ensures uniqueness even without real BSSID
                import hashlib
                hash_input = f"{ssid}:{channel}:{rssi}".encode()
                hash_digest = hashlib.md5(hash_input).hexdigest()
                bssid = f"{hash_digest[0:2]}:{hash_digest[2:4]}:{hash_digest[4:6]}:{hash_digest[6:8]}:{hash_digest[8:10]}:{hash_digest[10:12]}".upper()
                
                # Calculate frequency
                if channel <= 14:  # 2.4GHz
                    frequency = 2.412 + (channel - 1) * 0.005
                else:  # 5GHz
                    frequency = 5.180 + (channel - 36) * 0.005
                
                # Determine bandwidth from line content
                bandwidth = 20
                if "40" in line:
                    bandwidth = 40
                elif "80" in line:
                    bandwidth = 80
                
                # Determine security
                security = "Open"
                if "RSN" in line or "WPA3" in line:
                    security = "WPA2/WPA3"
                elif "WPA" in line:
                    security = "WPA"
                elif "WEP" in line:
                    security = "WEP"
                elif "NONE" in line:
                    security = "Open"
                else:
                    security = "WPA2"  # Default for most modern networks
                
                ap = AccessPoint(
                    ssid=ssid if ssid else f"Hidden_{bssid[-8:]}",
                    bssid=bssid,
                    channel=channel,
                    frequency=frequency,
                    signal_strength=rssi,
                    security=security,
                    bandwidth=bandwidth
                )
                aps[bssid] = ap
                
            except (ValueError, IndexError) as e:
                # Skip malformed lines
                continue
        
        return aps
    
    def _scan_wifi_linux(self) -> Dict[str, AccessPoint]:
        """Scan WiFi networks on Linux using iwlist"""
        try:
            # Find wireless interface
            cmd = ["iwconfig"]
            result = subprocess.run(cmd, capture_output=True, text=True)
            wifi_interface = None
            
            for line in result.stdout.split('\n'):
                if "IEEE 802.11" in line:
                    wifi_interface = line.split()[0]
                    break
            
            if not wifi_interface:
                return {}
            
            # Scan networks
            cmd = ["sudo", "iwlist", wifi_interface, "scan"]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode != 0:
                return {}
            
            # Parse results
            aps = {}
            current_ap = None
            
            for line in result.stdout.split('\n'):
                line = line.strip()
                
                if "Cell" in line and "Address:" in line:
                    if current_ap:
                        aps[current_ap.bssid] = current_ap
                    
                    bssid = line.split("Address:")[1].strip()
                    current_ap = AccessPoint(
                        ssid="",
                        bssid=bssid,
                        channel=1,
                        frequency=2.412,
                        signal_strength=-50,
                        security="Open"
                    )
                
                elif current_ap:
                    if "ESSID:" in line:
                        current_ap.ssid = line.split('"')[1] if '"' in line else ""
                    elif "Channel:" in line:
                        current_ap.channel = int(line.split("Channel:")[1])
                    elif "Frequency:" in line:
                        freq_str = line.split("Frequency:")[1].split()[0]
                        current_ap.frequency = float(freq_str)
                    elif "Signal level=" in line:
                        signal = line.split("Signal level=")[1].split()[0]
                        if "/" in signal:
                            current_ap.signal_strength = int(signal.split("/")[0])
                        else:
                            current_ap.signal_strength = int(signal)
                    elif "Encryption key:" in line:
                        if "on" in line:
                            current_ap.security = "WEP/WPA"
            
            if current_ap:
                aps[current_ap.bssid] = current_ap
            
            return aps
            
        except Exception as e:
            print(f"Error scanning WiFi on Linux: {e}")
            return {}
    
    def _scan_wifi_windows(self) -> Dict[str, AccessPoint]:
        """Scan WiFi networks on Windows using netsh"""
        try:
            cmd = ["netsh", "wlan", "show", "networks", "mode=bssid"]
            result = subprocess.run(cmd, capture_output=True, text=True, shell=True)
            
            if result.returncode != 0:
                return {}
            
            # Parse results
            aps = {}
            current_ssid = ""
            current_ap = None
            
            for line in result.stdout.split('\n'):
                line = line.strip()
                
                if line.startswith("SSID"):
                    parts = line.split(":")
                    if len(parts) > 1:
                        current_ssid = parts[1].strip()
                
                elif "BSSID" in line and ":" in line:
                    if current_ap:
                        aps[current_ap.bssid] = current_ap
                    
                    bssid = line.split(":", 1)[1].strip()
                    current_ap = AccessPoint(
                        ssid=current_ssid,
                        bssid=bssid,
                        channel=1,
                        frequency=2.412,
                        signal_strength=-50,
                        security="Open"
                    )
                
                elif current_ap:
                    if "Signal" in line and "%" in line:
                        signal_percent = int(line.split(":")[1].strip().replace("%", ""))
                        # Convert percentage to dBm (approximate)
                        current_ap.signal_strength = (signal_percent / 2) - 100
                    elif "Channel" in line:
                        current_ap.channel = int(line.split(":")[1].strip())
                        # Calculate frequency
                        if current_ap.channel <= 14:
                            current_ap.frequency = 2.412 + (current_ap.channel - 1) * 0.005
                        else:
                            current_ap.frequency = 5.180 + (current_ap.channel - 36) * 0.005
                    elif "Authentication" in line:
                        current_ap.security = line.split(":")[1].strip()
            
            if current_ap:
                aps[current_ap.bssid] = current_ap
            
            return aps
            
        except Exception as e:
            print(f"Error scanning WiFi on Windows: {e}")
            return {}
    
    def analyze_interference(self) -> Dict[str, List[Dict]]:
        """Analyze interference between access points"""
        interference_report = {
            "co_channel": [],
            "adjacent_channel": [],
            "overlapping": []
        }
        
        # Update AP list
        self.access_points = self.scan_wifi_networks()
        
        # Build channel map
        self.interference_map.clear()
        for ap in self.access_points.values():
            for channel in ap.channel_width:
                self.interference_map[channel].append(ap)
        
        # Analyze co-channel interference
        for channel, aps in self.interference_map.items():
            if len(aps) > 1:
                # Multiple APs on same channel
                for i, ap1 in enumerate(aps):
                    for ap2 in aps[i+1:]:
                        if ap1.signal_strength > -80 and ap2.signal_strength > -80:
                            interference_report["co_channel"].append({
                                "channel": channel,
                                "ap1": ap1.ssid,
                                "ap1_signal": ap1.signal_strength,
                                "ap2": ap2.ssid,
                                "ap2_signal": ap2.signal_strength,
                                "severity": self._calculate_interference_severity(
                                    ap1.signal_strength, ap2.signal_strength
                                )
                            })
        
        # Analyze adjacent channel interference (2.4GHz only)
        for channel in range(1, 12):  # Channels 1-11
            if channel in self.interference_map:
                for offset in [-1, 1]:
                    adj_channel = channel + offset
                    if adj_channel in self.interference_map:
                        for ap1 in self.interference_map[channel]:
                            for ap2 in self.interference_map[adj_channel]:
                                if ap1.signal_strength > -85 and ap2.signal_strength > -85:
                                    interference_report["adjacent_channel"].append({
                                        "channel1": channel,
                                        "channel2": adj_channel,
                                        "ap1": ap1.ssid,
                                        "ap2": ap2.ssid,
                                        "severity": "medium"
                                    })
        
        # Analyze bandwidth overlap
        for ap in self.access_points.values():
            if ap.bandwidth > 20:
                overlapping_aps = []
                for channel in ap.channel_width:
                    for other_ap in self.interference_map[channel]:
                        if other_ap.bssid != ap.bssid:
                            overlapping_aps.append(other_ap)
                
                if overlapping_aps:
                    interference_report["overlapping"].append({
                        "ap": ap.ssid,
                        "bandwidth": ap.bandwidth,
                        "overlapping_with": [a.ssid for a in overlapping_aps],
                        "severity": "high" if len(overlapping_aps) > 2 else "medium"
                    })
        
        return interference_report
    
    def _calculate_interference_severity(self, signal1: int, signal2: int) -> str:
        """Calculate interference severity based on signal strengths"""
        diff = abs(signal1 - signal2)
        
        if diff < 10:
            return "critical"  # Similar signal strengths cause most interference
        elif diff < 20:
            return "high"
        elif diff < 30:
            return "medium"
        else:
            return "low"
    
    def calculate_snr(self, signal_strength: int, noise_floor: int = -95) -> float:
        """Calculate Signal-to-Noise Ratio"""
        return signal_strength - noise_floor
    
    def analyze_signal_quality(self, bssid: str) -> Optional[SignalQuality]:
        """Analyze signal quality for a specific AP"""
        if bssid not in self.access_points:
            return None
        
        ap = self.access_points[bssid]
        
        # Estimate noise floor based on channel congestion
        channel_aps = len(self.interference_map[ap.channel])
        noise_floor = -95 + (channel_aps * 3)  # More APs = higher noise
        
        # Calculate SNR
        snr = self.calculate_snr(ap.signal_strength, noise_floor)
        
        # Estimate data rates based on signal strength and SNR
        if snr >= 40:
            tx_rate = 300  # Excellent signal
            mcs_index = 7
        elif snr >= 30:
            tx_rate = 150  # Good signal
            mcs_index = 5
        elif snr >= 20:
            tx_rate = 72   # Fair signal
            mcs_index = 3
        else:
            tx_rate = 24   # Poor signal
            mcs_index = 1
        
        # Estimate retry and error rates based on interference
        retry_rate = max(0, (30 - snr) * 2)  # Higher SNR = lower retry rate
        error_rate = max(0, (25 - snr) * 1.5)
        
        return SignalQuality(
            snr=snr,
            noise_floor=noise_floor,
            tx_rate=tx_rate,
            rx_rate=tx_rate * 0.8,  # RX typically slightly lower
            retry_rate=min(retry_rate, 50),
            error_rate=min(error_rate, 30),
            mcs_index=mcs_index
        )
    
    def discover_network_topology(self) -> Dict[str, NetworkNode]:
        """Discover network topology using various methods"""
        topology = {}
        
        # Get local network info
        local_ip = self._get_local_ip()
        subnet = self._get_subnet(local_ip)
        
        # Find gateway
        gateway_ip = self._get_default_gateway()
        if gateway_ip:
            topology[gateway_ip] = NetworkNode(
                ip_address=gateway_ip,
                mac_address=self._get_mac_address(gateway_ip),
                hostname="gateway",
                device_type="router",
                hop_count=1
            )
        
        # Scan local subnet
        active_hosts = self._scan_subnet(subnet)
        
        for ip in active_hosts:
            if ip not in topology:
                mac = self._get_mac_address(ip)
                hostname = self._get_hostname(ip)
                
                topology[ip] = NetworkNode(
                    ip_address=ip,
                    mac_address=mac,
                    hostname=hostname,
                    device_type=self._guess_device_type(hostname, mac),
                    latency=self._measure_latency(ip)
                )
        
        # Trace routes to identify topology
        for ip in list(topology.keys())[:5]:  # Limit to prevent long execution
            route = self._trace_route(ip)
            for i, hop_ip in enumerate(route):
                if hop_ip and hop_ip not in topology:
                    topology[hop_ip] = NetworkNode(
                        ip_address=hop_ip,
                        mac_address="unknown",
                        hostname=self._get_hostname(hop_ip),
                        device_type="router",
                        hop_count=i + 1
                    )
        
        self.network_topology = topology
        return topology
    
    def _get_local_ip(self) -> str:
        """Get local IP address"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"
    
    def _get_subnet(self, ip: str) -> str:
        """Get subnet from IP address (assuming /24)"""
        parts = ip.split('.')
        return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    
    def _get_default_gateway(self) -> Optional[str]:
        """Get default gateway IP"""
        try:
            if self.system == "Darwin" or self.system == "Linux":
                cmd = ["netstat", "-rn"]
                result = subprocess.run(cmd, capture_output=True, text=True)
                for line in result.stdout.split('\n'):
                    if "default" in line or "0.0.0.0" in line:
                        parts = line.split()
                        if len(parts) > 1:
                            gateway = parts[1]
                            if self._is_valid_ip(gateway):
                                return gateway
            elif self.system == "Windows":
                cmd = ["ipconfig"]
                result = subprocess.run(cmd, capture_output=True, text=True, shell=True)
                for line in result.stdout.split('\n'):
                    if "Default Gateway" in line:
                        parts = line.split(":")
                        if len(parts) > 1:
                            gateway = parts[1].strip()
                            if self._is_valid_ip(gateway):
                                return gateway
        except:
            pass
        return None
    
    def _is_valid_ip(self, ip: str) -> bool:
        """Check if string is valid IP address"""
        try:
            socket.inet_aton(ip)
            return True
        except:
            return False
    
    def _scan_subnet(self, subnet: str) -> List[str]:
        """Scan subnet for active hosts"""
        active_hosts = []
        
        # Simple ping scan (limited to avoid long execution)
        base_ip = subnet.split('/')[0]
        parts = base_ip.split('.')
        
        for i in range(1, 20):  # Scan first 20 IPs
            ip = f"{parts[0]}.{parts[1]}.{parts[2]}.{i}"
            if self._ping_host(ip):
                active_hosts.append(ip)
        
        return active_hosts
    
    def _ping_host(self, ip: str, timeout: int = 1) -> bool:
        """Ping a host to check if it's active"""
        try:
            if self.system == "Windows":
                cmd = ["ping", "-n", "1", "-w", str(timeout * 1000), ip]
            else:
                cmd = ["ping", "-c", "1", "-W", str(timeout), ip]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            return result.returncode == 0
        except:
            return False
    
    def _get_mac_address(self, ip: str) -> str:
        """Get MAC address for IP"""
        try:
            if self.system == "Darwin" or self.system == "Linux":
                cmd = ["arp", "-n", ip]
            else:
                cmd = ["arp", "-a", ip]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            # Parse MAC address from output
            mac_pattern = r"([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}"
            match = re.search(mac_pattern, result.stdout)
            
            if match:
                return match.group(0)
        except:
            pass
        
        return "unknown"
    
    def _get_hostname(self, ip: str) -> str:
        """Get hostname for IP"""
        try:
            return socket.gethostbyaddr(ip)[0]
        except:
            return ip
    
    def _guess_device_type(self, hostname: str, mac: str) -> str:
        """Guess device type based on hostname and MAC"""
        hostname_lower = hostname.lower()
        
        if any(x in hostname_lower for x in ["router", "gateway", "gw"]):
            return "router"
        elif any(x in hostname_lower for x in ["switch", "sw"]):
            return "switch"
        elif any(x in hostname_lower for x in ["ap", "access-point", "wifi"]):
            return "access_point"
        elif any(x in hostname_lower for x in ["printer", "print"]):
            return "printer"
        elif any(x in hostname_lower for x in ["phone", "mobile", "android", "iphone"]):
            return "mobile"
        elif any(x in hostname_lower for x in ["tv", "roku", "chromecast", "appletv"]):
            return "media_device"
        
        # Check MAC OUI for known manufacturers
        if mac != "unknown":
            mac_prefix = mac[:8].upper().replace(":", "").replace("-", "")
            # Add more OUI mappings as needed
            if mac_prefix.startswith("00005E"):
                return "router"
        
        return "device"
    
    def _measure_latency(self, ip: str) -> float:
        """Measure latency to host"""
        try:
            if self.system == "Windows":
                cmd = ["ping", "-n", "3", ip]
            else:
                cmd = ["ping", "-c", "3", ip]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            # Parse average latency
            if "Average" in result.stdout:  # Windows
                match = re.search(r"Average = (\d+)ms", result.stdout)
            else:  # Unix-like
                match = re.search(r"avg = ([\d.]+)", result.stdout)
            
            if match:
                return float(match.group(1))
        except:
            pass
        
        return 0.0
    
    def _trace_route(self, destination: str, max_hops: int = 10) -> List[str]:
        """Trace route to destination"""
        route = []
        
        try:
            if self.system == "Windows":
                cmd = ["tracert", "-h", str(max_hops), "-w", "1000", destination]
            else:
                cmd = ["traceroute", "-m", str(max_hops), "-w", "1", destination]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            # Parse route
            ip_pattern = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
            
            for line in result.stdout.split('\n'):
                matches = re.findall(ip_pattern, line)
                if matches:
                    # Take the first IP in the line (skip duplicates)
                    route.append(matches[0])
        except:
            pass
        
        return route
    
    def generate_coverage_map(self) -> Dict[str, Dict]:
        """Generate WiFi coverage map with signal strength zones"""
        coverage_map = {
            "excellent": [],  # -50 dBm or better
            "good": [],       # -50 to -60 dBm
            "fair": [],       # -60 to -70 dBm
            "weak": [],       # -70 to -80 dBm
            "dead_zones": []  # -80 dBm or worse
        }
        
        for ap in self.access_points.values():
            signal = ap.signal_strength
            
            if signal >= -50:
                coverage_map["excellent"].append({
                    "ssid": ap.ssid,
                    "signal": signal,
                    "channel": ap.channel
                })
            elif signal >= -60:
                coverage_map["good"].append({
                    "ssid": ap.ssid,
                    "signal": signal,
                    "channel": ap.channel
                })
            elif signal >= -70:
                coverage_map["fair"].append({
                    "ssid": ap.ssid,
                    "signal": signal,
                    "channel": ap.channel
                })
            elif signal >= -80:
                coverage_map["weak"].append({
                    "ssid": ap.ssid,
                    "signal": signal,
                    "channel": ap.channel
                })
            else:
                coverage_map["dead_zones"].append({
                    "ssid": ap.ssid,
                    "signal": signal,
                    "channel": ap.channel
                })
        
        return coverage_map
    
    def analyze_channel_utilization(self) -> Dict[int, Dict]:
        """Analyze channel utilization across the spectrum"""
        utilization = {}
        
        # 2.4GHz channels
        for channel in range(1, 14):
            aps_on_channel = self.interference_map.get(channel, [])
            
            utilization[channel] = {
                "frequency": "2.4GHz",
                "ap_count": len(aps_on_channel),
                "total_signal_power": sum(ap.signal_strength for ap in aps_on_channel),
                "strongest_signal": max([ap.signal_strength for ap in aps_on_channel], default=-100),
                "recommended": channel in [1, 6, 11] and len(aps_on_channel) < 3
            }
        
        # 5GHz channels (common ones)
        for channel in [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165]:
            aps_on_channel = self.interference_map.get(channel, [])
            
            utilization[channel] = {
                "frequency": "5GHz",
                "ap_count": len(aps_on_channel),
                "total_signal_power": sum(ap.signal_strength for ap in aps_on_channel),
                "strongest_signal": max([ap.signal_strength for ap in aps_on_channel], default=-100),
                "recommended": len(aps_on_channel) < 2
            }
        
        return utilization
    
    def recommend_ap_placement(self) -> List[Dict]:
        """Generate AP placement recommendations"""
        recommendations = []
        
        # Analyze current coverage
        coverage = self.generate_coverage_map()
        
        # Check for dead zones
        if coverage["dead_zones"]:
            recommendations.append({
                "issue": "Dead zones detected",
                "severity": "critical",
                "recommendation": "Add access points to cover dead zones",
                "details": f"Found {len(coverage['dead_zones'])} areas with very weak signal"
            })
        
        # Check for weak coverage areas
        if len(coverage["weak"]) > len(coverage["excellent"]):
            recommendations.append({
                "issue": "Weak coverage predominant",
                "severity": "high",
                "recommendation": "Reposition existing APs or add additional APs",
                "details": "More areas have weak signal than excellent signal"
            })
        
        # Check channel distribution
        channel_util = self.analyze_channel_utilization()
        
        # Find overcrowded channels
        for channel, info in channel_util.items():
            if info["ap_count"] > 3 and info["frequency"] == "2.4GHz":
                recommendations.append({
                    "issue": f"Channel {channel} overcrowded",
                    "severity": "high",
                    "recommendation": f"Move some APs from channel {channel} to less crowded channels",
                    "details": f"{info['ap_count']} APs detected on channel {channel}"
                })
        
        # Recommend 5GHz usage
        ghz_24_count = sum(1 for c, i in channel_util.items() if i["frequency"] == "2.4GHz" and i["ap_count"] > 0)
        ghz_5_count = sum(1 for c, i in channel_util.items() if i["frequency"] == "5GHz" and i["ap_count"] > 0)
        
        if ghz_24_count > ghz_5_count * 2:
            recommendations.append({
                "issue": "Underutilization of 5GHz band",
                "severity": "medium",
                "recommendation": "Configure more APs to use 5GHz band for better performance",
                "details": f"2.4GHz: {ghz_24_count} channels used, 5GHz: {ghz_5_count} channels used"
            })
        
        # Check for co-channel interference
        interference = self.analyze_interference()
        
        if len(interference["co_channel"]) > 5:
            recommendations.append({
                "issue": "High co-channel interference",
                "severity": "high",
                "recommendation": "Reconfigure APs to use non-overlapping channels (1, 6, 11 for 2.4GHz)",
                "details": f"{len(interference['co_channel'])} instances of co-channel interference detected"
            })
        
        return recommendations
    
    def diagnose_issue(self, issue_type: str) -> Dict:
        """Diagnose specific network issues"""
        diagnosis = {
            "issue": issue_type,
            "findings": [],
            "recommendations": [],
            "metrics": {}
        }
        
        if issue_type == "slow_wifi":
            # Check interference
            interference = self.analyze_interference()
            
            if interference["co_channel"]:
                diagnosis["findings"].append("Co-channel interference detected")
                diagnosis["recommendations"].append("Change WiFi channel to avoid interference")
            
            # Check signal quality
            coverage = self.generate_coverage_map()
            if coverage["weak"] or coverage["dead_zones"]:
                diagnosis["findings"].append("Weak signal strength in some areas")
                diagnosis["recommendations"].append("Move closer to AP or add signal booster")
            
            # Check channel congestion
            channel_util = self.analyze_channel_utilization()
            congested = [c for c, i in channel_util.items() if i["ap_count"] > 3]
            if congested:
                diagnosis["findings"].append(f"Congested channels: {congested}")
                diagnosis["recommendations"].append("Switch to less congested channel")
            
        elif issue_type == "random_disconnections":
            # Check signal stability
            weak_signals = [ap for ap in self.access_points.values() if ap.signal_strength < -70]
            
            if weak_signals:
                diagnosis["findings"].append("Weak signal from some access points")
                diagnosis["recommendations"].append("Improve AP placement or increase transmission power")
            
            # Check for roaming issues
            same_ssid_aps = defaultdict(list)
            for ap in self.access_points.values():
                same_ssid_aps[ap.ssid].append(ap)
            
            for ssid, aps in same_ssid_aps.items():
                if len(aps) > 1:
                    signals = [ap.signal_strength for ap in aps]
                    if max(signals) - min(signals) < 10:
                        diagnosis["findings"].append(f"Multiple APs with similar signal strength for {ssid}")
                        diagnosis["recommendations"].append("Adjust AP power to create clear roaming boundaries")
        
        elif issue_type == "cannot_connect":
            # Check if any networks are visible
            if not self.access_points:
                diagnosis["findings"].append("No WiFi networks detected")
                diagnosis["recommendations"].append("Check if WiFi adapter is enabled")
            else:
                # Check signal strength
                strong_signals = [ap for ap in self.access_points.values() if ap.signal_strength > -60]
                if not strong_signals:
                    diagnosis["findings"].append("All detected networks have weak signals")
                    diagnosis["recommendations"].append("Move closer to access point")
                
                # Check security
                secured = [ap for ap in self.access_points.values() if ap.security != "Open"]
                if len(secured) == len(self.access_points):
                    diagnosis["findings"].append("All networks require authentication")
                    diagnosis["recommendations"].append("Ensure you have correct credentials")
        
        elif issue_type == "time_based_slowdown":
            diagnosis["findings"].append("Time-based performance issues detected")
            diagnosis["recommendations"].append("Check for scheduled tasks or backups during slow periods")
            diagnosis["recommendations"].append("Monitor channel utilization during peak hours")
            diagnosis["recommendations"].append("Consider implementing QoS policies")
        
        return diagnosis
    
    def generate_report(self) -> Dict:
        """Generate comprehensive diagnostic report"""
        # Scan networks
        self.scan_wifi_networks()
        
        # Gather all diagnostics
        report = {
            "timestamp": datetime.now().isoformat(),
            "summary": {
                "total_aps_detected": len(self.access_points),
                "channels_in_use": list(self.interference_map.keys()),
                "topology_nodes": len(self.network_topology)
            },
            "coverage_analysis": self.generate_coverage_map(),
            "interference_analysis": self.analyze_interference(),
            "channel_utilization": self.analyze_channel_utilization(),
            "topology": {
                ip: {
                    "hostname": node.hostname,
                    "type": node.device_type,
                    "latency": node.latency
                }
                for ip, node in self.network_topology.items()
            },
            "recommendations": self.recommend_ap_placement()
        }
        
        # Add signal quality for strongest APs
        strongest_aps = sorted(
            self.access_points.values(),
            key=lambda x: x.signal_strength,
            reverse=True
        )[:5]
        
        report["signal_quality"] = {}
        for ap in strongest_aps:
            quality = self.analyze_signal_quality(ap.bssid)
            if quality:
                report["signal_quality"][ap.ssid] = {
                    "signal": ap.signal_strength,
                    "snr": quality.snr,
                    "estimated_speed": f"{quality.tx_rate} Mbps",
                    "retry_rate": f"{quality.retry_rate:.1f}%",
                    "error_rate": f"{quality.error_rate:.1f}%"
                }
        
        return report