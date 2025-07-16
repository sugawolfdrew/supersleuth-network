"""
WiFi infrastructure analysis and optimization module
"""

import subprocess
import re
import json
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime
import platform
import math

from ..core.diagnostic import BaseDiagnostic, DiagnosticResult
from ..core.authorization import AuthorizationRequest, RiskLevel
from ..utils.logger import get_logger


class WiFiAnalysis(BaseDiagnostic):
    """Enterprise WiFi deployment analysis and optimization"""
    
    def __init__(self, config: Dict):
        super().__init__(config)
        self.scan_duration = config.get('scan_duration', 30)  # seconds
        self.include_hidden = config.get('include_hidden', True)
        self.channel_analysis = config.get('channel_analysis', True)
        self.signal_threshold_dbm = config.get('signal_threshold', -70)  # Good signal
        
    def validate_prerequisites(self) -> bool:
        """Check if prerequisites are met"""
        
        # Platform-specific tool checking
        system = platform.system()
        
        if system == "Darwin":  # macOS
            required_tools = ['airport']
            self.wifi_tool = 'airport'
        elif system == "Linux":
            required_tools = ['iwlist', 'iw']
            self.wifi_tool = 'iw' if self._check_tool_available('iw') else 'iwlist'
        elif system == "Windows":
            # Windows uses netsh, usually available
            required_tools = []
            self.wifi_tool = 'netsh'
        else:
            self.logger.error(f"Unsupported platform: {system}")
            return False
        
        for tool in required_tools:
            if not self._check_tool_available(tool):
                self.logger.error(f"Required tool '{tool}' not available")
                return False
        
        return True
    
    def get_authorization_required(self) -> Dict[str, Any]:
        """Return authorization requirements"""
        return {
            'read_only': True,
            'system_changes': False,
            'data_access': 'wifi_metadata_only',
            'risk_level': RiskLevel.LOW.value,
            'requires_approval': True,
            'note': 'Passive WiFi scanning only'
        }
    
    def run(self) -> DiagnosticResult:
        """Execute WiFi analysis"""
        
        result = DiagnosticResult("WiFi Infrastructure Analysis")
        
        try:
            self.logger.info("Starting WiFi infrastructure analysis")
            
            # Scan for WiFi networks
            networks = self._scan_wifi_networks()
            
            # Analyze current connection
            current_connection = self._get_current_wifi_info()
            
            # Perform channel analysis
            channel_analysis = self._analyze_channels(networks) if self.channel_analysis else None
            
            # Signal strength mapping
            signal_analysis = self._analyze_signal_coverage(networks)
            
            # Security assessment
            security_analysis = self._analyze_wifi_security(networks)
            
            # Enterprise features assessment
            enterprise_analysis = self._analyze_enterprise_features(networks)
            
            # WiFi 6/6E readiness
            wifi6_readiness = self._assess_wifi6_readiness(networks)
            
            # Complete result
            result.complete({
                'networks_found': len(networks),
                'current_connection': current_connection,
                'networks': networks,
                'channel_analysis': channel_analysis,
                'signal_analysis': signal_analysis,
                'security_analysis': security_analysis,
                'enterprise_analysis': enterprise_analysis,
                'wifi6_readiness': wifi6_readiness
            })
            
            # Add recommendations
            self._add_wifi_recommendations(result, networks, channel_analysis, 
                                         security_analysis, signal_analysis)
            
        except Exception as e:
            self.logger.error(f"WiFi analysis failed: {str(e)}")
            result.fail(str(e))
        
        return result
    
    def _check_tool_available(self, tool: str) -> bool:
        """Check if a tool is available on the system"""
        try:
            subprocess.run(['which', tool], capture_output=True, check=True)
            return True
        except subprocess.CalledProcessError:
            return False
    
    def _scan_wifi_networks(self) -> List[Dict[str, Any]]:
        """Scan for available WiFi networks"""
        
        system = platform.system()
        
        if system == "Darwin":
            return self._scan_wifi_macos()
        elif system == "Linux":
            return self._scan_wifi_linux()
        elif system == "Windows":
            return self._scan_wifi_windows()
        else:
            return []
    
    def _scan_wifi_macos(self) -> List[Dict[str, Any]]:
        """Scan WiFi networks on macOS"""
        
        networks = []
        
        try:
            # Use airport utility
            cmd = ['/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport', '-s']
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                
                for line in lines[1:]:  # Skip header
                    parts = line.split()
                    if len(parts) >= 7:
                        network = {
                            'ssid': parts[0],
                            'bssid': parts[1],
                            'rssi': int(parts[2]),
                            'channel': int(parts[3]),
                            'ht': parts[4],  # High Throughput (802.11n)
                            'cc': parts[5],  # Country Code
                            'security': ' '.join(parts[6:]),
                            'discovered_at': datetime.now().isoformat()
                        }
                        
                        # Determine frequency band
                        if network['channel'] <= 14:
                            network['band'] = '2.4GHz'
                        else:
                            network['band'] = '5GHz'
                        
                        # Calculate signal quality
                        network['signal_quality'] = self._calculate_signal_quality(network['rssi'])
                        
                        networks.append(network)
            
        except Exception as e:
            self.logger.error(f"Error scanning WiFi on macOS: {str(e)}")
        
        return networks
    
    def _scan_wifi_linux(self) -> List[Dict[str, Any]]:
        """Scan WiFi networks on Linux"""
        
        networks = []
        
        try:
            # Get wireless interface
            interface = self._get_wireless_interface_linux()
            if not interface:
                self.logger.error("No wireless interface found")
                return networks
            
            if self.wifi_tool == 'iw':
                # Modern tool
                cmd = ['sudo', 'iw', 'dev', interface, 'scan']
                result = subprocess.run(cmd, capture_output=True, text=True)
                
                if result.returncode == 0:
                    networks = self._parse_iw_scan(result.stdout)
            else:
                # Legacy tool
                cmd = ['sudo', 'iwlist', interface, 'scan']
                result = subprocess.run(cmd, capture_output=True, text=True)
                
                if result.returncode == 0:
                    networks = self._parse_iwlist_scan(result.stdout)
            
        except Exception as e:
            self.logger.error(f"Error scanning WiFi on Linux: {str(e)}")
        
        return networks
    
    def _scan_wifi_windows(self) -> List[Dict[str, Any]]:
        """Scan WiFi networks on Windows"""
        
        networks = []
        
        try:
            # Use netsh wlan
            cmd = ['netsh', 'wlan', 'show', 'networks', 'mode=bssid']
            result = subprocess.run(cmd, capture_output=True, text=True, shell=True)
            
            if result.returncode == 0:
                networks = self._parse_netsh_scan(result.stdout)
            
        except Exception as e:
            self.logger.error(f"Error scanning WiFi on Windows: {str(e)}")
        
        return networks
    
    def _get_wireless_interface_linux(self) -> Optional[str]:
        """Get the wireless interface name on Linux"""
        
        try:
            # Try to find wireless interfaces
            cmd = ['ls', '/sys/class/net/']
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                interfaces = result.stdout.strip().split()
                
                for interface in interfaces:
                    # Check if it's a wireless interface
                    wireless_check = f'/sys/class/net/{interface}/wireless'
                    try:
                        subprocess.run(['test', '-d', wireless_check], check=True)
                        return interface
                    except:
                        continue
        except:
            pass
        
        # Common wireless interface names
        common_names = ['wlan0', 'wlp2s0', 'wlp3s0', 'wifi0']
        for name in common_names:
            try:
                subprocess.run(['ip', 'link', 'show', name], capture_output=True, check=True)
                return name
            except:
                continue
        
        return None
    
    def _parse_iw_scan(self, output: str) -> List[Dict[str, Any]]:
        """Parse output from 'iw scan' command"""
        
        networks = []
        current_network = None
        
        for line in output.split('\n'):
            line = line.strip()
            
            if line.startswith('BSS'):
                # New network
                if current_network:
                    networks.append(current_network)
                
                bssid = line.split()[1].rstrip('(on')
                current_network = {
                    'bssid': bssid,
                    'discovered_at': datetime.now().isoformat()
                }
            
            elif current_network:
                if line.startswith('signal:'):
                    # Extract RSSI
                    rssi_match = re.search(r'(-?\d+\.\d+)\s*dBm', line)
                    if rssi_match:
                        current_network['rssi'] = int(float(rssi_match.group(1)))
                
                elif line.startswith('SSID:'):
                    current_network['ssid'] = line.split(':', 1)[1].strip()
                
                elif line.startswith('freq:'):
                    freq = int(line.split(':')[1].strip())
                    current_network['frequency'] = freq
                    current_network['channel'] = self._freq_to_channel(freq)
                    current_network['band'] = '2.4GHz' if freq < 3000 else '5GHz'
                
                elif 'RSN:' in line or 'WPA:' in line:
                    if 'security' not in current_network:
                        current_network['security'] = []
                    current_network['security'].append(line.split(':')[0].strip())
        
        # Don't forget the last network
        if current_network:
            networks.append(current_network)
        
        # Post-process networks
        for network in networks:
            if 'rssi' in network:
                network['signal_quality'] = self._calculate_signal_quality(network['rssi'])
            if 'security' in network:
                network['security'] = ', '.join(network['security'])
            else:
                network['security'] = 'Open'
        
        return networks
    
    def _parse_iwlist_scan(self, output: str) -> List[Dict[str, Any]]:
        """Parse output from 'iwlist scan' command"""
        
        networks = []
        current_network = None
        
        for line in output.split('\n'):
            line = line.strip()
            
            if 'Cell' in line and 'Address:' in line:
                # New network
                if current_network:
                    networks.append(current_network)
                
                bssid = line.split('Address:')[1].strip()
                current_network = {
                    'bssid': bssid,
                    'discovered_at': datetime.now().isoformat()
                }
            
            elif current_network:
                if 'ESSID:' in line:
                    ssid = line.split('ESSID:')[1].strip('"')
                    current_network['ssid'] = ssid
                
                elif 'Channel:' in line:
                    channel = int(line.split('Channel:')[1].strip())
                    current_network['channel'] = channel
                    current_network['band'] = '2.4GHz' if channel <= 14 else '5GHz'
                
                elif 'Signal level=' in line:
                    # Extract signal level
                    signal_match = re.search(r'Signal level=(-?\d+)', line)
                    if signal_match:
                        current_network['rssi'] = int(signal_match.group(1))
                
                elif 'Encryption key:' in line:
                    if 'off' in line.lower():
                        current_network['security'] = 'Open'
                    else:
                        current_network['security'] = 'Encrypted'
                
                elif 'IE:' in line and ('WPA' in line or 'RSN' in line):
                    # Update security info
                    if 'WPA2' in line:
                        current_network['security'] = 'WPA2'
                    elif 'WPA' in line:
                        current_network['security'] = 'WPA'
        
        # Don't forget the last network
        if current_network:
            networks.append(current_network)
        
        # Post-process networks
        for network in networks:
            if 'rssi' in network:
                network['signal_quality'] = self._calculate_signal_quality(network['rssi'])
        
        return networks
    
    def _parse_netsh_scan(self, output: str) -> List[Dict[str, Any]]:
        """Parse output from 'netsh wlan show networks' command"""
        
        networks = []
        current_network = None
        
        for line in output.split('\n'):
            line = line.strip()
            
            if line.startswith('SSID'):
                ssid_match = re.match(r'SSID\s*\d*\s*:\s*(.+)', line)
                if ssid_match:
                    if current_network:
                        networks.append(current_network)
                    
                    current_network = {
                        'ssid': ssid_match.group(1),
                        'discovered_at': datetime.now().isoformat()
                    }
            
            elif current_network:
                if line.startswith('BSSID'):
                    bssid_match = re.match(r'BSSID\s*\d*\s*:\s*([0-9a-fA-F:]+)', line)
                    if bssid_match:
                        current_network['bssid'] = bssid_match.group(1)
                
                elif line.startswith('Signal'):
                    signal_match = re.match(r'Signal\s*:\s*(\d+)%', line)
                    if signal_match:
                        # Convert percentage to approximate dBm
                        percent = int(signal_match.group(1))
                        current_network['rssi'] = self._percent_to_dbm(percent)
                        current_network['signal_quality'] = percent
                
                elif line.startswith('Channel'):
                    channel_match = re.match(r'Channel\s*:\s*(\d+)', line)
                    if channel_match:
                        channel = int(channel_match.group(1))
                        current_network['channel'] = channel
                        current_network['band'] = '2.4GHz' if channel <= 14 else '5GHz'
                
                elif line.startswith('Authentication'):
                    current_network['authentication'] = line.split(':')[1].strip()
                
                elif line.startswith('Encryption'):
                    encryption = line.split(':')[1].strip()
                    auth = current_network.get('authentication', '')
                    
                    if encryption == 'None':
                        current_network['security'] = 'Open'
                    else:
                        current_network['security'] = f"{auth} {encryption}".strip()
        
        # Don't forget the last network
        if current_network:
            networks.append(current_network)
        
        return networks
    
    def _freq_to_channel(self, freq_mhz: int) -> int:
        """Convert frequency to WiFi channel number"""
        
        # 2.4 GHz band
        if 2412 <= freq_mhz <= 2484:
            if freq_mhz == 2484:
                return 14
            else:
                return (freq_mhz - 2412) // 5 + 1
        
        # 5 GHz band
        elif 5180 <= freq_mhz <= 5825:
            return (freq_mhz - 5180) // 5 + 36
        
        # 6 GHz band (WiFi 6E)
        elif 5925 <= freq_mhz <= 7125:
            return (freq_mhz - 5925) // 5 + 1
        
        else:
            return 0
    
    def _percent_to_dbm(self, percent: int) -> int:
        """Convert signal percentage to approximate dBm"""
        
        # Rough conversion - actual mapping varies by driver
        if percent >= 90:
            return -50
        elif percent >= 80:
            return -60
        elif percent >= 70:
            return -70
        elif percent >= 60:
            return -75
        elif percent >= 50:
            return -80
        elif percent >= 40:
            return -85
        else:
            return -90
    
    def _calculate_signal_quality(self, rssi: int) -> int:
        """Calculate signal quality percentage from RSSI"""
        
        # Convert RSSI to quality percentage
        if rssi >= -50:
            return 100
        elif rssi >= -60:
            return 90
        elif rssi >= -70:
            return 75
        elif rssi >= -80:
            return 50
        elif rssi >= -90:
            return 25
        else:
            return 10
    
    def _get_current_wifi_info(self) -> Optional[Dict[str, Any]]:
        """Get information about current WiFi connection"""
        
        system = platform.system()
        
        try:
            if system == "Darwin":
                # macOS
                cmd = ['/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport', '-I']
                result = subprocess.run(cmd, capture_output=True, text=True)
                
                if result.returncode == 0:
                    return self._parse_airport_info(result.stdout)
            
            elif system == "Linux":
                # Linux - try iwconfig
                interface = self._get_wireless_interface_linux()
                if interface:
                    cmd = ['iwconfig', interface]
                    result = subprocess.run(cmd, capture_output=True, text=True)
                    
                    if result.returncode == 0:
                        return self._parse_iwconfig_info(result.stdout)
            
            elif system == "Windows":
                # Windows
                cmd = ['netsh', 'wlan', 'show', 'interfaces']
                result = subprocess.run(cmd, capture_output=True, text=True, shell=True)
                
                if result.returncode == 0:
                    return self._parse_netsh_interface(result.stdout)
        
        except Exception as e:
            self.logger.error(f"Error getting current WiFi info: {str(e)}")
        
        return None
    
    def _parse_airport_info(self, output: str) -> Dict[str, Any]:
        """Parse macOS airport -I output"""
        
        info = {}
        
        for line in output.split('\n'):
            if ':' in line:
                key, value = line.split(':', 1)
                key = key.strip()
                value = value.strip()
                
                if key == 'SSID':
                    info['ssid'] = value
                elif key == 'BSSID':
                    info['bssid'] = value
                elif key == 'channel':
                    info['channel'] = int(value.split(',')[0])
                elif key == 'agrCtlRSSI':
                    info['rssi'] = int(value)
                elif key == 'state':
                    info['state'] = value
                elif key == 'lastTxRate':
                    info['tx_rate'] = int(value)
                elif key == 'maxRate':
                    info['max_rate'] = int(value)
        
        if 'rssi' in info:
            info['signal_quality'] = self._calculate_signal_quality(info['rssi'])
        
        return info if info else None
    
    def _parse_iwconfig_info(self, output: str) -> Dict[str, Any]:
        """Parse Linux iwconfig output"""
        
        info = {}
        
        # Extract SSID
        ssid_match = re.search(r'ESSID:"([^"]+)"', output)
        if ssid_match:
            info['ssid'] = ssid_match.group(1)
        
        # Extract Access Point (BSSID)
        ap_match = re.search(r'Access Point:\s*([0-9A-Fa-f:]+)', output)
        if ap_match:
            info['bssid'] = ap_match.group(1)
        
        # Extract signal level
        signal_match = re.search(r'Signal level=(-?\d+)\s*dBm', output)
        if signal_match:
            info['rssi'] = int(signal_match.group(1))
            info['signal_quality'] = self._calculate_signal_quality(info['rssi'])
        
        # Extract bit rate
        rate_match = re.search(r'Bit Rate=(\d+\.?\d*)\s*Mb/s', output)
        if rate_match:
            info['tx_rate'] = float(rate_match.group(1))
        
        return info if info else None
    
    def _parse_netsh_interface(self, output: str) -> Dict[str, Any]:
        """Parse Windows netsh wlan show interfaces output"""
        
        info = {}
        
        for line in output.split('\n'):
            if ':' in line:
                key, value = line.split(':', 1)
                key = key.strip()
                value = value.strip()
                
                if key == 'SSID':
                    info['ssid'] = value
                elif key == 'BSSID':
                    info['bssid'] = value
                elif key == 'Channel':
                    info['channel'] = int(value)
                elif key == 'Signal':
                    # Convert percentage to approximate dBm
                    percent = int(value.rstrip('%'))
                    info['rssi'] = self._percent_to_dbm(percent)
                    info['signal_quality'] = percent
                elif key == 'Receive rate (Mbps)':
                    info['rx_rate'] = float(value)
                elif key == 'Transmit rate (Mbps)':
                    info['tx_rate'] = float(value)
        
        return info if info else None
    
    def _analyze_channels(self, networks: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze channel utilization and interference"""
        
        self.logger.info("Analyzing WiFi channels...")
        
        channel_analysis = {
            '2.4GHz': self._analyze_band_channels(networks, '2.4GHz'),
            '5GHz': self._analyze_band_channels(networks, '5GHz'),
            'recommendations': []
        }
        
        # Add channel recommendations
        for band, analysis in [('2.4GHz', channel_analysis['2.4GHz']), 
                               ('5GHz', channel_analysis['5GHz'])]:
            if analysis['networks_count'] > 0:
                best_channels = analysis['best_channels'][:3]
                if best_channels:
                    channel_analysis['recommendations'].append({
                        'band': band,
                        'recommended_channels': best_channels,
                        'reason': f"Least congested channels in {band} band"
                    })
        
        return channel_analysis
    
    def _analyze_band_channels(self, networks: List[Dict[str, Any]], band: str) -> Dict[str, Any]:
        """Analyze channels for a specific band"""
        
        band_networks = [n for n in networks if n.get('band') == band]
        
        # Count networks per channel
        channel_counts = {}
        for network in band_networks:
            channel = network.get('channel')
            if channel:
                channel_counts[channel] = channel_counts.get(channel, 0) + 1
        
        # Calculate channel congestion considering overlap
        channel_congestion = {}
        
        if band == '2.4GHz':
            # 2.4GHz channels overlap
            for ch in range(1, 15):
                congestion = 0
                for network in band_networks:
                    net_channel = network.get('channel')
                    if net_channel:
                        # Calculate overlap
                        channel_diff = abs(ch - net_channel)
                        if channel_diff == 0:
                            congestion += 1.0
                        elif channel_diff < 5:
                            congestion += (5 - channel_diff) / 5.0
                
                channel_congestion[ch] = congestion
        else:
            # 5GHz channels don't overlap (when using 20MHz width)
            for network in band_networks:
                channel = network.get('channel')
                if channel:
                    channel_congestion[channel] = channel_counts.get(channel, 0)
        
        # Find best channels
        all_channels = list(range(1, 15)) if band == '2.4GHz' else [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 149, 153, 157, 161, 165]
        
        best_channels = sorted(all_channels, key=lambda ch: channel_congestion.get(ch, 0))
        
        return {
            'networks_count': len(band_networks),
            'channel_distribution': channel_counts,
            'channel_congestion': channel_congestion,
            'best_channels': best_channels,
            'most_congested_channel': max(channel_counts.items(), key=lambda x: x[1])[0] if channel_counts else None
        }
    
    def _analyze_signal_coverage(self, networks: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze signal strength and coverage"""
        
        self.logger.info("Analyzing signal coverage...")
        
        # Categorize networks by signal strength
        signal_categories = {
            'excellent': [],  # >= -60 dBm
            'good': [],       # -60 to -70 dBm
            'fair': [],       # -70 to -80 dBm
            'poor': []        # < -80 dBm
        }
        
        for network in networks:
            rssi = network.get('rssi')
            if rssi is not None:
                if rssi >= -60:
                    signal_categories['excellent'].append(network)
                elif rssi >= -70:
                    signal_categories['good'].append(network)
                elif rssi >= -80:
                    signal_categories['fair'].append(network)
                else:
                    signal_categories['poor'].append(network)
        
        # Identify potential coverage issues
        coverage_issues = []
        
        # Check for weak client network
        client_networks = [n for n in networks if self._is_client_network(n)]
        for network in client_networks:
            if network.get('rssi', -100) < self.signal_threshold_dbm:
                coverage_issues.append({
                    'type': 'weak_signal',
                    'network': network['ssid'],
                    'rssi': network.get('rssi'),
                    'location': 'Current scan location'
                })
        
        return {
            'signal_distribution': {
                'excellent': len(signal_categories['excellent']),
                'good': len(signal_categories['good']),
                'fair': len(signal_categories['fair']),
                'poor': len(signal_categories['poor'])
            },
            'average_rssi': sum(n.get('rssi', 0) for n in networks if 'rssi' in n) / len([n for n in networks if 'rssi' in n]) if networks else 0,
            'coverage_issues': coverage_issues,
            'signal_categories': signal_categories
        }
    
    def _analyze_wifi_security(self, networks: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze WiFi security posture"""
        
        self.logger.info("Analyzing WiFi security...")
        
        security_stats = {
            'open': 0,
            'wep': 0,
            'wpa': 0,
            'wpa2': 0,
            'wpa3': 0,
            'enterprise': 0
        }
        
        security_issues = []
        
        for network in networks:
            security = network.get('security', '').lower()
            
            if not security or security == 'open':
                security_stats['open'] += 1
                if self._is_client_network(network):
                    security_issues.append({
                        'severity': 'critical',
                        'type': 'open_network',
                        'network': network['ssid'],
                        'message': 'Client network has no encryption'
                    })
            elif 'wep' in security:
                security_stats['wep'] += 1
                if self._is_client_network(network):
                    security_issues.append({
                        'severity': 'critical',
                        'type': 'weak_encryption',
                        'network': network['ssid'],
                        'message': 'WEP encryption is obsolete and easily cracked'
                    })
            elif 'wpa3' in security:
                security_stats['wpa3'] += 1
            elif 'wpa2' in security:
                security_stats['wpa2'] += 1
                if self._is_client_network(network) and 'enterprise' not in security:
                    security_issues.append({
                        'severity': 'medium',
                        'type': 'outdated_encryption',
                        'network': network['ssid'],
                        'message': 'Consider upgrading to WPA3 for enhanced security'
                    })
            elif 'wpa' in security:
                security_stats['wpa'] += 1
                if self._is_client_network(network):
                    security_issues.append({
                        'severity': 'high',
                        'type': 'weak_encryption',
                        'network': network['ssid'],
                        'message': 'WPA is outdated - upgrade to WPA2 or WPA3'
                    })
            
            if 'enterprise' in security or '802.1x' in security:
                security_stats['enterprise'] += 1
        
        # Check for rogue APs (same SSID, different BSSID)
        ssid_bssid_map = {}
        for network in networks:
            ssid = network.get('ssid', '')
            bssid = network.get('bssid', '')
            
            if ssid and self._is_client_network(network):
                if ssid not in ssid_bssid_map:
                    ssid_bssid_map[ssid] = []
                ssid_bssid_map[ssid].append(bssid)
        
        for ssid, bssids in ssid_bssid_map.items():
            if len(set(bssids)) > 1:
                security_issues.append({
                    'severity': 'high',
                    'type': 'potential_rogue_ap',
                    'network': ssid,
                    'message': f'Multiple access points detected with same SSID ({len(set(bssids))} different BSSIDs)'
                })
        
        return {
            'security_distribution': security_stats,
            'security_score': self._calculate_security_score(security_stats, len(networks)),
            'security_issues': security_issues,
            'recommendations': self._generate_security_recommendations(security_stats, security_issues)
        }
    
    def _analyze_enterprise_features(self, networks: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze enterprise WiFi features"""
        
        self.logger.info("Analyzing enterprise features...")
        
        enterprise_features = {
            '802.1x': 0,
            'radius': 0,
            'guest_isolation': 0,
            'band_steering': 0,
            'fast_roaming': 0
        }
        
        # Identify enterprise features
        for network in networks:
            security = network.get('security', '').lower()
            
            if '802.1x' in security or 'enterprise' in security:
                enterprise_features['802.1x'] += 1
            
            if 'radius' in security:
                enterprise_features['radius'] += 1
        
        # Check for band steering (same SSID on different bands)
        ssid_bands = {}
        for network in networks:
            ssid = network.get('ssid', '')
            band = network.get('band', '')
            
            if ssid and self._is_client_network(network):
                if ssid not in ssid_bands:
                    ssid_bands[ssid] = set()
                ssid_bands[ssid].add(band)
        
        for ssid, bands in ssid_bands.items():
            if len(bands) > 1:
                enterprise_features['band_steering'] += 1
        
        return {
            'features_detected': enterprise_features,
            'enterprise_ready': enterprise_features['802.1x'] > 0,
            'recommendations': self._generate_enterprise_recommendations(enterprise_features)
        }
    
    def _assess_wifi6_readiness(self, networks: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Assess WiFi 6/6E deployment readiness"""
        
        self.logger.info("Assessing WiFi 6/6E readiness...")
        
        # Check for WiFi 6 indicators
        wifi6_indicators = {
            'wifi6_networks': 0,
            'wifi6e_networks': 0,
            'high_density_channels': 0,
            'wide_channels': 0
        }
        
        for network in networks:
            # Check for WiFi 6 indicators in network capabilities
            ht = network.get('ht', '')
            
            # Check if using 6GHz band (WiFi 6E)
            channel = network.get('channel', 0)
            if channel > 200:  # 6GHz channels
                wifi6_indicators['wifi6e_networks'] += 1
            
            # Check for high-efficiency indicators
            if 'ax' in str(ht).lower():
                wifi6_indicators['wifi6_networks'] += 1
        
        # Assess current environment density
        network_density = len(networks)
        density_assessment = 'low'
        if network_density > 50:
            density_assessment = 'high'
        elif network_density > 20:
            density_assessment = 'medium'
        
        return {
            'current_indicators': wifi6_indicators,
            'network_density': density_assessment,
            'wifi6_recommended': density_assessment in ['medium', 'high'],
            'benefits': self._list_wifi6_benefits(density_assessment)
        }
    
    def _is_client_network(self, network: Dict[str, Any]) -> bool:
        """Determine if a network belongs to the client"""
        
        # In a real implementation, this would check against known client SSIDs
        # For now, use heuristics
        
        ssid = network.get('ssid', '').lower()
        
        # Common guest network patterns
        guest_patterns = ['guest', 'visitor', 'public', 'free']
        
        # Assume non-guest networks are client networks
        return not any(pattern in ssid for pattern in guest_patterns)
    
    def _calculate_security_score(self, security_stats: Dict[str, int], total_networks: int) -> int:
        """Calculate overall security score"""
        
        if total_networks == 0:
            return 0
        
        score = 100
        
        # Deduct points for security issues
        score -= security_stats['open'] * 20
        score -= security_stats['wep'] * 15
        score -= security_stats['wpa'] * 10
        
        # Add points for good security
        score += security_stats['wpa3'] * 5
        score += security_stats['enterprise'] * 10
        
        return max(0, min(100, score))
    
    def _generate_security_recommendations(self, security_stats: Dict[str, int], 
                                          security_issues: List[Dict[str, Any]]) -> List[str]:
        """Generate security recommendations"""
        
        recommendations = []
        
        # Critical issues first
        for issue in security_issues:
            if issue['severity'] == 'critical':
                if issue['type'] == 'open_network':
                    recommendations.append(
                        f"URGENT: Enable WPA3 encryption on {issue['network']}"
                    )
                elif issue['type'] == 'weak_encryption':
                    recommendations.append(
                        f"URGENT: Upgrade encryption on {issue['network']} from {issue['message']}"
                    )
        
        # General recommendations
        if security_stats['wpa2'] > 0 and security_stats['wpa3'] == 0:
            recommendations.append(
                "Consider upgrading access points to support WPA3 for enhanced security"
            )
        
        if security_stats['enterprise'] == 0:
            recommendations.append(
                "Implement 802.1X enterprise authentication for better access control"
            )
        
        return recommendations
    
    def _generate_enterprise_recommendations(self, features: Dict[str, int]) -> List[str]:
        """Generate enterprise feature recommendations"""
        
        recommendations = []
        
        if features['802.1x'] == 0:
            recommendations.append(
                "Deploy RADIUS server for enterprise authentication (802.1X)"
            )
        
        if features['band_steering'] == 0:
            recommendations.append(
                "Enable band steering to optimize client connections between 2.4GHz and 5GHz"
            )
        
        if features['guest_isolation'] == 0:
            recommendations.append(
                "Implement guest network isolation to protect internal resources"
            )
        
        return recommendations
    
    def _list_wifi6_benefits(self, density: str) -> List[str]:
        """List WiFi 6 benefits based on environment"""
        
        benefits = [
            "Increased network capacity for high-density environments",
            "Lower latency for real-time applications",
            "Better battery life for connected devices (TWT)",
            "Improved security with WPA3 mandatory"
        ]
        
        if density == 'high':
            benefits.insert(0, "OFDMA technology will significantly improve performance in your high-density environment")
        
        return benefits
    
    def _add_wifi_recommendations(self, result: DiagnosticResult, networks: List[Dict[str, Any]],
                                 channel_analysis: Optional[Dict[str, Any]],
                                 security_analysis: Dict[str, Any],
                                 signal_analysis: Dict[str, Any]):
        """Add WiFi-specific recommendations"""
        
        # Channel optimization
        if channel_analysis:
            for band_rec in channel_analysis.get('recommendations', []):
                result.add_recommendation(
                    f"Switch {band_rec['band']} to channel {band_rec['recommended_channels'][0]} "
                    f"to reduce interference"
                )
        
        # Security recommendations
        for rec in security_analysis.get('recommendations', []):
            result.add_recommendation(rec)
        
        # Coverage recommendations
        if signal_analysis['coverage_issues']:
            result.add_recommendation(
                "Deploy additional access points or adjust AP placement to address coverage gaps"
            )
        
        # High density recommendations
        if len(networks) > 30:
            result.add_recommendation(
                "High WiFi density detected - consider implementing dynamic channel allocation"
            )