import logging
import json
import time
import subprocess
import socket
import threading
import sys
import concurrent.futures
from pathlib import Path
from typing import Dict, List, Optional


class EnhancedScanning:
    """
    Enhanced vulnerability scanning module with CVE detection
    """

    def __init__(self, workspace: str = "./workspace"):
        """
        Initialize the vulnerability scanning module

        Args:
            workspace: Directory to store results and logs
        """
        self.workspace = Path(workspace)
        self.workspace.mkdir(exist_ok=True)
        self._setup_logging()

        # Progress tracking for GUI updates
        self.progress_callbacks = []
        self.status_callbacks = []

        # Timeout controls
        self.scan_stop_event = threading.Event()

        # Default thread pool for parallel scanning
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=10)

    def _setup_logging(self):
        """Setup logging configuration"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(self.workspace / 'scanning.log'),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger(__name__)

    def add_progress_callback(self, callback):
        """Add a callback function to receive progress updates"""
        self.progress_callbacks.append(callback)

    def add_status_callback(self, callback):
        """Add a callback function to receive status messages"""
        self.status_callbacks.append(callback)

    def update_progress(self, value):
        """Update progress value (0-100)"""
        for callback in self.progress_callbacks:
            try:
                callback(value)
            except Exception as e:
                self.logger.error(f"Error in progress callback: {str(e)}")

    def update_status(self, message, message_type="info"):
        """Update status message"""
        for callback in self.status_callbacks:
            try:
                callback(message, message_type)
            except Exception as e:
                self.logger.error(f"Error in status callback: {str(e)}")

        # Also log the message
        if message_type == "error":
            self.logger.error(message)
        elif message_type == "warning":
            self.logger.warning(message)
        else:
            self.logger.info(message)

    def tcp_connect_scan(self, target, ports):
        """
        Perform a simple TCP connect scan to identify open ports

        Args:
            target: Target IP address
            ports: List of ports to scan

        Returns:
            Dict of open ports with service guesses
        """
        open_ports = {}

        self.update_status(f"Starting TCP connect scan on {target} ({len(ports)} ports)")

        # Common service names by port
        common_services = {
            21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
            80: "http", 443: "https", 445: "smb", 3306: "mysql", 3389: "rdp",
            8080: "http-alt", 1433: "mssql", 5432: "postgresql"
        }

        def check_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((target, port))
                if result == 0:
                    service = common_services.get(port, "unknown")
                    return port, service
                sock.close()
            except:
                pass
            return None

        # Use ThreadPoolExecutor for parallel scanning
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            futures = {executor.submit(check_port, port): port for port in ports}

            # Process results as they complete
            completed = 0
            for future in concurrent.futures.as_completed(futures):
                completed += 1
                if completed % 100 == 0:
                    progress = int(completed / len(ports) * 100)
                    self.update_progress(progress)

                result = future.result()
                if result:
                    port, service = result
                    open_ports[str(port)] = {
                        "name": service,
                        "product": "unknown",
                        "version": "unknown"
                    }
                    self.update_status(f"Found open port {port} ({service}) on {target}")

        self.update_status(f"TCP connect scan complete. Found {len(open_ports)} open ports on {target}")
        return open_ports

    def banner_grab(self, target, ports):
        """
        Perform banner grabbing on open ports to identify services and versions

        Args:
            target: Target IP address
            ports: Dict of open ports from tcp_connect_scan

        Returns:
            Updated ports dict with banner information
        """
        self.update_status(f"Starting banner grabbing on {target}")

        for port, details in ports.items():
            try:
                port_num = int(port)
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                sock.connect((target, port_num))

                # Send different prompts based on the service
                if details["name"] == "http" or details["name"] == "https":
                    sock.send(b"GET / HTTP/1.1\r\nHost: " + target.encode() + b"\r\n\r\n")
                elif details["name"] == "ftp":
                    # Just connect, FTP servers usually send a banner
                    pass
                elif details["name"] == "smtp":
                    sock.send(b"EHLO example.com\r\n")
                elif details["name"] == "ssh":
                    # Just connect, SSH servers usually send a banner
                    pass
                else:
                    # Generic request
                    sock.send(b"\r\n")

                # Receive banner
                banner = sock.recv(1024)
                sock.close()

                banner_str = banner.decode('utf-8', errors='ignore').strip()

                # Update port details with banner information
                if banner_str:
                    details["banner"] = banner_str

                    # Try to extract product and version information
                    if "Server:" in banner_str:
                        server_line = [line for line in banner_str.split('\n') if "Server:" in line]
                        if server_line:
                            server_info = server_line[0].split("Server:")[1].strip()
                            details["product"] = server_info

                            # Try to extract version
                            if "/" in server_info:
                                parts = server_info.split("/")
                                if len(parts) > 1:
                                    details["product"] = parts[0].strip()
                                    details["version"] = parts[1].strip()

                    # SSH specific parsing
                    elif "SSH" in banner_str:
                        parts = banner_str.split(" ")
                        if len(parts) > 1:
                            details["product"] = "SSH"
                            for part in parts:
                                if "-" in part:
                                    details["version"] = part
                                    break

                    self.update_status(f"Banner grabbed on port {port}: {banner_str[:40]}...")

            except Exception as e:
                self.logger.error(f"Error grabbing banner on port {port}: {str(e)}")

        self.update_status(f"Banner grabbing complete for {target}")
        return ports

    def detect_os(self, target):
        """
        Attempt to detect OS using ping TTL values and other heuristics

        Args:
            target: Target IP address

        Returns:
            Dict with OS detection information
        """
        os_info = {
            "os_name": "Unknown",
            "os_type": "unknown",
            "confidence": "low"
        }

        # Try to ping the target and analyze TTL
        try:
            if sys.platform == "win32":
                ping_cmd = ["ping", "-n", "1", target]
            else:
                ping_cmd = ["ping", "-c", "1", target]

            process = subprocess.Popen(
                ping_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            stdout, stderr = process.communicate(timeout=5)

            # Extract TTL value
            ttl_value = None

            if sys.platform == "win32":
                for line in stdout.splitlines():
                    if "TTL=" in line:
                        ttl_part = line.split("TTL=")[1].split()[0]
                        ttl_value = int(ttl_part)
                        break
            else:
                for line in stdout.splitlines():
                    if "ttl=" in line.lower():
                        ttl_part = line.lower().split("ttl=")[1].split()[0]
                        ttl_value = int(ttl_part)
                        break

            # Analyze TTL to guess OS
            if ttl_value:
                if ttl_value <= 64:
                    os_info["os_name"] = "Linux/Unix"
                    os_info["os_type"] = "linux"
                    os_info["confidence"] = "medium"
                elif ttl_value <= 128:
                    os_info["os_name"] = "Windows"
                    os_info["os_type"] = "windows"
                    os_info["confidence"] = "medium"
                elif ttl_value <= 255:
                    os_info["os_name"] = "Solaris/AIX"
                    os_info["os_type"] = "unix"
                    os_info["confidence"] = "medium"

        except Exception as e:
            self.logger.error(f"Error in OS detection: {str(e)}")

        return os_info

    def check_known_vulnerabilities(self, service, product, version):
        """
        Check for known vulnerabilities based on service, product and version

        Args:
            service: Service name (e.g., ssh, http)
            product: Product name (e.g., OpenSSH, Apache)
            version: Version string

        Returns:
            List of potential vulnerabilities with CVE references
        """
        vulnerabilities = []

        # SSH vulnerabilities
        if service == "ssh" and product.lower() == "openssh" and version:
            if self._version_compare(version, "7.7") < 0:
                vulnerabilities.append({
                    "name": "OpenSSH Username Enumeration",
                    "description": f"OpenSSH {version} is vulnerable to username enumeration via timing side-channel",
                    "severity": "Medium",
                    "cve": "CVE-2018-15473"
                })

            if self._version_compare(version, "5.9") < 0:
                vulnerabilities.append({
                    "name": "OpenSSH Weak Algorithms",
                    "description": f"OpenSSH {version} uses potentially weak algorithms",
                    "severity": "Medium",
                    "cve": "CVE-2016-6210"
                })

        # FTP vulnerabilities
        elif service == "ftp":
            if "vsftpd" in product.lower() and version == "2.3.4":
                vulnerabilities.append({
                    "name": "vsFTPd Backdoor",
                    "description": "vsFTPd 2.3.4 contains a backdoor triggered on smileys in username",
                    "severity": "Critical",
                    "cve": "CVE-2011-2523"
                })

        # SMB vulnerabilities
        elif service == "smb" or service == "microsoft-ds" or service == "445":
            if "windows" in product.lower() and any(v in version.lower() for v in ["xp", "2003", "vista", "2008"]):
                vulnerabilities.append({
                    "name": "EternalBlue SMB Vulnerability",
                    "description": "System may be vulnerable to MS17-010 (EternalBlue)",
                    "severity": "Critical",
                    "cve": "CVE-2017-0144"
                })

        # HTTP vulnerabilities
        elif service == "http" or service == "https":
            if "apache" in product.lower():
                if self._version_compare(version, "2.4.50") < 0 and self._version_compare(version, "2.4.0") >= 0:
                    vulnerabilities.append({
                        "name": "Apache Path Traversal",
                        "description": f"Apache {version} may be vulnerable to path traversal",
                        "severity": "High",
                        "cve": "CVE-2021-41773"
                    })

            elif "nginx" in product.lower():
                if self._version_compare(version, "1.5.0") < 0:
                    vulnerabilities.append({
                        "name": "Nginx Information Disclosure",
                        "description": f"Nginx {version} may leak sensitive information",
                        "severity": "Medium",
                        "cve": "CVE-2013-4547"
                    })

        # RDP vulnerabilities
        elif service == "rdp" or service == "ms-wbt-server" or service == "3389":
            vulnerabilities.append({
                "name": "Potential RDP Vulnerabilities",
                "description": "RDP service might be vulnerable to BlueKeep or similar vulnerabilities",
                "severity": "High",
                "cve": "CVE-2019-0708"
            })

        return vulnerabilities

    def _version_compare(self, version1, version2):
        """
        Compare version strings

        Args:
            version1: First version string
            version2: Second version string

        Returns:
            -1 if version1 < version2, 0 if equal, 1 if version1 > version2
        """
        try:
            # Extract only digits and dots, remove letters and other characters
            import re

            # Convert versions to lists of integers
            v1_parts = [int(part) for part in re.sub(r'[^\d.]', '', version1).split('.')]
            v2_parts = [int(part) for part in re.sub(r'[^\d.]', '', version2).split('.')]

            # Pad the shorter version with zeros
            max_length = max(len(v1_parts), len(v2_parts))
            v1_parts.extend([0] * (max_length - len(v1_parts)))
            v2_parts.extend([0] * (max_length - len(v2_parts)))

            # Compare parts
            for i in range(max_length):
                if v1_parts[i] < v2_parts[i]:
                    return -1
                elif v1_parts[i] > v2_parts[i]:
                    return 1

            return 0  # Versions are equal
        except:
            # If version comparison fails, return 0 (assume equal)
            return 0

    def scan_host(self, target, ports=None):
        """
        Scan a target host for open ports and vulnerabilities

        Args:
            target: Target IP address
            ports: List of ports to scan (optional)

        Returns:
            Dict containing scan results
        """
        self.update_status(f"Starting scan of {target}")
        self.update_progress(10)

        scan_results = {}
        scan_results[target] = {}

        start_time = time.time()

        # Step 1: Identify open ports
        if not ports:
            # Default to scanning common ports
            common_ports = [21, 22, 23, 25, 53, 80, 443, 445, 3306, 3389, 8080, 1433, 5432,
                            5900, 8443, 161, 389, 636, 139, 5060, 5061]
            open_port_details = self.tcp_connect_scan(target, common_ports)
            scan_results[target] = open_port_details
        else:
            # Use provided ports
            open_port_details = self.tcp_connect_scan(target, ports)
            scan_results[target] = open_port_details

        self.update_progress(40)

        # Step 2: Banner grabbing for service identification
        scan_results[target] = self.banner_grab(target, scan_results[target])

        self.update_progress(60)

        # Step 3: OS detection via TTL and other heuristics
        os_type = self.detect_os(target)
        scan_results["os_info"] = os_type

        self.update_progress(70)

        # Step 4: Check for known vulnerabilities based on service versions
        for port, details in scan_results[target].items():
            product = details.get("product", "unknown")
            version = details.get("version", "")
            service = details.get("name", "unknown")

            vulnerabilities = self.check_known_vulnerabilities(service, product, version)
            if vulnerabilities:
                details["vulnerabilities"] = vulnerabilities
                self.update_status(f"Found {len(vulnerabilities)} potential vulnerabilities on {target}:{port}",
                                   "warning")

        # Calculate scan duration and complete the scan
        duration = time.time() - start_time
        self.update_status(f"Scan of {target} completed in {int(duration)} seconds")
        self.update_progress(100)

        return scan_results

    def analyze_vulnerabilities(self, scan_results):
        """
        Extract vulnerabilities from scan results

        Args:
            scan_results: Results from scan_host method

        Returns:
            Dict containing vulnerabilities by host and port
        """
        vulnerabilities = {}

        for host, ports in scan_results.items():
            if host == "os_info":  # Skip the os_info key
                continue

            vulnerabilities[host] = {}

            for port, details in ports.items():
                service = details.get("name", "unknown")

                vuln_list = []

                # Add detected vulnerabilities
                if "vulnerabilities" in details:
                    for vuln in details["vulnerabilities"]:
                        vuln_entry = {
                            "script": vuln.get("name", "unknown"),
                            "output": vuln.get("description", "") + f" (CVE: {vuln.get('cve', 'Unknown')})",
                            "severity": vuln.get("severity", "Medium"),
                            "cve": vuln.get("cve", "")
                        }
                        vuln_list.append(vuln_entry)

                # If no vulnerabilities were found, add a basic port scan finding
                if not vuln_list:
                    vuln_list.append({
                        "script": "Port Discovery",
                        "output": f"Open port {port} ({service}) - {details.get('product', 'unknown')} {details.get('version', '')}",
                        "severity": "Info",
                        "cve": ""
                    })

                if vuln_list:
                    vulnerabilities[host][port] = {
                        "service": service,
                        "vulnerabilities": vuln_list
                    }

        return vulnerabilities

    def perform_comprehensive_scan(self, target, scan_type="both"):
        """
        Perform a comprehensive scan on a target

        Args:
            target: Target IP address or hostname
            scan_type: Type of scan ("system", "network", or "both")

        Returns:
            Dict containing scan results
        """
        self.update_status(f"Starting {scan_type} vulnerability scan on {target}")

        start_time = time.time()

        # Perform the scan
        scan_results = self.scan_host(target)

        # Extract vulnerabilities
        vuln_results = self.analyze_vulnerabilities(scan_results)

        # Extract os info
        os_type = scan_results.get("os_info", {}).get("os_type", "unknown")

        # Count vulnerabilities by severity
        vuln_count = 0
        critical_count = 0
        high_count = 0
        medium_count = 0
        low_count = 0

        for host, ports in vuln_results.items():
            for port, details in ports.items():
                for vuln in details.get("vulnerabilities", []):
                    vuln_count += 1
                    severity = vuln.get("severity", "")
                    if severity == "Critical":
                        critical_count += 1
                    elif severity == "High":
                        high_count += 1
                    elif severity == "Medium":
                        medium_count += 1
                    elif severity == "Low":
                        low_count += 1

        # Create results in standard format
        results = {
            "scan_results": [{
                "host": target,
                "os_type": os_type,
                "vulnerabilities": vuln_results.get(target, {})
            }],
            "summary": {
                "target": target,
                "scan_type": scan_type,
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "vulnerabilities_found": vuln_count,
                "critical_vulnerabilities": critical_count,
                "high_vulnerabilities": high_count,
                "medium_vulnerabilities": medium_count,
                "low_vulnerabilities": low_count,
                "duration_seconds": int(time.time() - start_time)
            }
        }

        # Extract services
        services = {}
        for port, details in scan_results.get(target, {}).items():
            service_name = details.get("name", "unknown")
            services[service_name] = int(port)

        results["scan_results"][0]["services"] = services

        # Save results
        self._save_results(results)

        # Create success message
        if vuln_count > 0:
            severity_summary = []
            if critical_count > 0:
                severity_summary.append(f"{critical_count} critical")
            if high_count > 0:
                severity_summary.append(f"{high_count} high")
            if medium_count > 0:
                severity_summary.append(f"{medium_count} medium")
            if low_count > 0:
                severity_summary.append(f"{low_count} low")

            severity_str = ", ".join(severity_summary)
            self.update_status(f"Scan completed successfully. Found {vuln_count} vulnerabilities ({severity_str})",
                               "success")
        else:
            self.update_status("Scan completed successfully. No vulnerabilities found.", "success")

        return results

    def _save_results(self, results):
        """Save scan results to a JSON file"""
        try:
            results_file = self.workspace / f'vuln_scan_{time.strftime("%Y%m%d_%H%M%S")}.json'
            with open(results_file, 'w') as f:
                json.dump(results, f, indent=4)
            self.update_status(f"Results saved to {results_file}")
        except Exception as e:
            self.update_status(f"Error saving results: {str(e)}", "error")


# Example usage
if __name__ == "__main__":
    # Setup basic progress and status callbacks
    def print_progress(value):
        print(f"Progress: {value}%")


    def print_status(message, message_type="info"):
        print(f"[{message_type.upper()}] {message}")


    # Create scanner with example workspace
    scanner = EnhancedScanning("./test_workspace")
    scanner.add_progress_callback(print_progress)
    scanner.add_status_callback(print_status)

    # Test on localhost or specified target
    target = "127.0.0.1"
    if len(sys.argv) > 1:
        target = sys.argv[1]

    print(f"Scanning target: {target}")
    results = scanner.perform_comprehensive_scan(target, "both")
    print(json.dumps(results, indent=2))