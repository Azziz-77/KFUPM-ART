import logging
import json
import time
import subprocess
import threading
import sys
import socket
import concurrent.futures
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List, Optional


class OpenVASScanner:
    """
    Vulnerability scanning module integrating with OpenVAS/GVM
    with fallback to basic port scanning
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

        # OpenVAS configuration
        self.openvas_host = "localhost"
        self.openvas_port = 9390
        self.openvas_username = "admin"
        self.openvas_password = "admin"

        # Test connection to OpenVAS
        self.openvas_available = self._test_openvas_connection()

        if not self.openvas_available:
            self.logger.warning("OpenVAS not available or misconfigured. Will use basic scanning capabilities.")

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

    def configure_openvas(self, host, port, username, password):
        """
        Configure OpenVAS connection settings

        Args:
            host: OpenVAS server hostname
            port: OpenVAS server port
            username: OpenVAS username
            password: OpenVAS password
        """
        self.openvas_host = host
        self.openvas_port = port
        self.openvas_username = username
        self.openvas_password = password

        # Test connection with new settings
        self.openvas_available = self._test_openvas_connection()

        if self.openvas_available:
            self.update_status("OpenVAS connection configured successfully", "success")
        else:
            self.update_status("Failed to connect to OpenVAS with provided settings", "error")

    def _test_openvas_connection(self):
        """Test connection to OpenVAS server using the Python GVM library"""
        try:
            # We need to run this as non-root, so use a separate Python process
            test_script = """
    import sys
    from gvm.connections import UnixSocketConnection
    from gvm.protocols.gmp import Gmp

    try:
        connection = UnixSocketConnection(path='/var/run/gvmd/gvmd.sock')
        with Gmp(connection) as gmp:
            gmp.authenticate('{username}', '{password}')
            version = gmp.get_version()
            print("Connected successfully")
        sys.exit(0)
    except Exception as e:
        print(f"Error: {{str(e)}}")
        sys.exit(1)
    """.format(username=self.openvas_username, password=self.openvas_password)

            # Write this script to a temporary file
            import tempfile
            with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
                f.write(test_script)
                temp_script = f.name

            # Run the script as the kali user
            cmd = ["sudo", "-u", "kali", "python3", temp_script]
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            stdout, stderr = process.communicate(timeout=10)

            # Clean up
            import os
            os.unlink(temp_script)

            if "Connected successfully" in stdout and process.returncode == 0:
                self.update_status("Successfully connected to OpenVAS", "info")
                return True
            else:
                self.update_status(f"Failed to connect to OpenVAS: {stdout} {stderr}", "warning")
                return False

        except Exception as e:
            self.logger.error(f"Error testing OpenVAS connection: {str(e)}")
            return False

    def run_openvas_scan(self, target, scan_type="full"):
        """
        Run an OpenVAS vulnerability scan

        Args:
            target: Target IP or hostname to scan
            scan_type: Type of scan (full, fast, etc.)

        Returns:
            Scan results dictionary
        """
        self.update_status(f"Starting OpenVAS scan on {target}", "info")
        self.update_progress(10)

        scan_id = None
        task_id = None

        try:
            # Create a target in OpenVAS
            target_name = f"scan_{int(time.time())}"

            create_target_cmd = [
                "gvm-cli",
                "--hostname", self.openvas_host,
                "--port", str(self.openvas_port),
                "--username", self.openvas_username,
                "--password", self.openvas_password,
                "socket",
                "--xml", f"<create_target><name>{target_name}</name><hosts>{target}</hosts></create_target>"
            ]

            process = subprocess.Popen(
                create_target_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            stdout, stderr = process.communicate(timeout=30)

            # Parse the target ID
            try:
                root = ET.fromstring(stdout)
                target_id = root.get('id')
                self.update_status(f"Created target with ID {target_id}", "info")
            except Exception as e:
                self.logger.error(f"Error parsing target ID: {str(e)}")
                return {"error": "Failed to create target"}

            self.update_progress(20)

            # Create a task
            config_id = ""
            if scan_type == "full":
                # Full and comprehensive scan
                config_id = "daba56c8-73ec-11df-a475-002264764cea"
            else:
                # Fast scan
                config_id = "74db13d6-7489-11df-91b9-002264764cea"

            scanner_id = "08b69003-5fc2-4037-a479-93b440211c73"  # OpenVAS Default Scanner

            create_task_cmd = [
                "gvm-cli",
                "--hostname", self.openvas_host,
                "--port", str(self.openvas_port),
                "--username", self.openvas_username,
                "--password", self.openvas_password,
                "socket",
                "--xml",
                f"<create_task><name>Scan {target}</name><target id=\"{target_id}\"/><config id=\"{config_id}\"/><scanner id=\"{scanner_id}\"/></create_task>"
            ]

            process = subprocess.Popen(
                create_task_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            stdout, stderr = process.communicate(timeout=30)

            # Parse the task ID
            try:
                root = ET.fromstring(stdout)
                task_id = root.get('id')
                self.update_status(f"Created task with ID {task_id}", "info")
            except Exception as e:
                self.logger.error(f"Error parsing task ID: {str(e)}")
                return {"error": "Failed to create task"}

            self.update_progress(30)

            # Start the scan
            start_task_cmd = [
                "gvm-cli",
                "--hostname", self.openvas_host,
                "--port", str(self.openvas_port),
                "--username", self.openvas_username,
                "--password", self.openvas_password,
                "socket",
                "--xml", f"<start_task task_id=\"{task_id}\"/>"
            ]

            process = subprocess.Popen(
                start_task_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            stdout, stderr = process.communicate(timeout=30)

            # Parse the report ID
            try:
                root = ET.fromstring(stdout)
                report_id = root.find(".//report_id").text
                self.update_status(f"Started scan with report ID {report_id}", "info")
            except Exception as e:
                self.logger.error(f"Error parsing report ID: {str(e)}")
                return {"error": "Failed to start scan"}

            self.update_progress(40)

            # Monitor scan progress
            status = "Running"
            progress = 0

            while status != "Done" and not self.scan_stop_event.is_set():
                # Check scan status
                get_task_cmd = [
                    "gvm-cli",
                    "--hostname", self.openvas_host,
                    "--port", str(self.openvas_port),
                    "--username", self.openvas_username,
                    "--password", self.openvas_password,
                    "socket",
                    "--xml", f"<get_tasks task_id=\"{task_id}\"/>"
                ]

                process = subprocess.Popen(
                    get_task_cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )

                stdout, stderr = process.communicate(timeout=30)

                try:
                    root = ET.fromstring(stdout)
                    status_elem = root.find(".//status")

                    if status_elem is not None:
                        status = status_elem.text

                    progress_elem = root.find(".//progress")
                    if progress_elem is not None:
                        progress = int(progress_elem.text)

                    self.update_status(f"Scan progress: {progress}% - {status}", "info")
                    self.update_progress(40 + int(progress * 0.5))  # Map to 40-90% of our progress
                except Exception as e:
                    self.logger.error(f"Error parsing scan status: {str(e)}")

                if status != "Done":
                    time.sleep(10)  # Check every 10 seconds

            if self.scan_stop_event.is_set():
                # Scan was canceled
                self.update_status("Scan canceled by user", "warning")
                return {"error": "Scan canceled by user"}

            self.update_progress(90)

            # Get scan results
            get_report_cmd = [
                "gvm-cli",
                "--hostname", self.openvas_host,
                "--port", str(self.openvas_port),
                "--username", self.openvas_username,
                "--password", self.openvas_password,
                "socket",
                "--xml", f"<get_results filter=\"report_id={report_id}\"/>"
            ]

            process = subprocess.Popen(
                get_report_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            stdout, stderr = process.communicate(timeout=60)

            # Save raw results
            results_file = self.workspace / f"openvas_results_{int(time.time())}.xml"
            with open(results_file, "w") as f:
                f.write(stdout)

            self.update_status(f"Raw results saved to {results_file}", "info")

            # Parse results
            vulnerabilities = self._parse_openvas_results(stdout)

            self.update_progress(100)
            self.update_status(f"Scan completed. Found {len(vulnerabilities)} vulnerabilities.", "success")

            # Format results
            scan_results = {
                "scan_results": [{
                    "host": target,
                    "os_type": self._detect_os_from_openvas(stdout),
                    "services": self._extract_services_from_openvas(stdout),
                    "vulnerabilities": self._format_openvas_vulnerabilities(vulnerabilities)
                }],
                "summary": {
                    "target": target,
                    "scan_type": scan_type,
                    "vulnerabilities_found": len(vulnerabilities),
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "scanner": "OpenVAS"
                }
            }

            return scan_results

        except Exception as e:
            self.logger.error(f"Error in OpenVAS scan: {str(e)}")
            return {"error": str(e)}
        finally:
            # Clean up the task if needed
            if task_id:
                try:
                    cleanup_cmd = [
                        "gvm-cli",
                        "--hostname", self.openvas_host,
                        "--port", str(self.openvas_port),
                        "--username", self.openvas_username,
                        "--password", self.openvas_password,
                        "socket",
                        "--xml", f"<delete_task task_id=\"{task_id}\"/>"
                    ]

                    subprocess.run(cleanup_cmd, timeout=10)
                except:
                    pass

    def _parse_openvas_results(self, xml_data):
        """
        Parse OpenVAS XML results into structured vulnerability data

        Args:
            xml_data: XML data from OpenVAS

        Returns:
            List of vulnerability dictionaries
        """
        vulnerabilities = []

        try:
            root = ET.fromstring(xml_data)
            result_elements = root.findall(".//result")

            for result in result_elements:
                # Skip info findings if present
                severity = result.find("severity")
                if severity is not None and float(severity.text) <= 0:
                    continue

                name_elem = result.find("name")
                description_elem = result.find("description")
                port_elem = result.find("port")

                vuln = {
                    "name": name_elem.text if name_elem is not None else "Unknown",
                    "description": description_elem.text if description_elem is not None else "",
                    "port": port_elem.text if port_elem is not None else "0",
                    "severity": self._convert_openvas_severity(severity.text if severity is not None else "0")
                }

                vulnerabilities.append(vuln)
        except Exception as e:
            self.logger.error(f"Error parsing OpenVAS results: {str(e)}")

        return vulnerabilities

    def _convert_openvas_severity(self, severity_value):
        """Convert OpenVAS severity to standardized severity string"""
        try:
            severity = float(severity_value)

            if severity >= 9.0:
                return "Critical"
            elif severity >= 7.0:
                return "High"
            elif severity >= 4.0:
                return "Medium"
            elif severity > 0:
                return "Low"
            else:
                return "Info"
        except:
            return "Medium"

    def _detect_os_from_openvas(self, xml_data):
        """Extract OS information from OpenVAS results"""
        os_info = {"os_type": "unknown"}

        try:
            root = ET.fromstring(xml_data)
            # Look for OS detection results
            os_elements = root.findall(".//result[name='OS Detection']")

            if os_elements:
                for os_elem in os_elements:
                    description = os_elem.find("description")
                    if description is not None and description.text:
                        os_text = description.text.lower()

                        if "windows" in os_text:
                            os_info["os_type"] = "windows"
                            break
                        elif "linux" in os_text:
                            os_info["os_type"] = "linux"
                            break
        except Exception as e:
            self.logger.error(f"Error detecting OS from OpenVAS results: {str(e)}")

        return os_info["os_type"]

    def _extract_services_from_openvas(self, xml_data):
        """Extract service information from OpenVAS results"""
        services = {}

        try:
            root = ET.fromstring(xml_data)
            # Look for service detection results
            port_elements = root.findall(".//port")

            for port_elem in port_elements:
                if port_elem.text and "/" in port_elem.text:
                    parts = port_elem.text.split("/")
                    if len(parts) >= 2:
                        port_num = parts[0]
                        protocol = parts[1]

                        # Try to get service name from surrounding elements
                        result = port_elem.getparent()
                        if result is not None:
                            name_elem = result.find("name")
                            if name_elem is not None and "service" in name_elem.text.lower():
                                service_name = name_elem.text.split("(")[0].strip()
                                services[service_name] = int(port_num)
                            else:
                                # Use common mappings
                                service_name = self._guess_service_from_port(port_num)
                                services[service_name] = int(port_num)
        except Exception as e:
            self.logger.error(f"Error extracting services from OpenVAS results: {str(e)}")

        return services

    def _guess_service_from_port(self, port):
        """Guess service name from common port numbers"""
        port_map = {
            "21": "ftp",
            "22": "ssh",
            "23": "telnet",
            "25": "smtp",
            "53": "dns",
            "80": "http",
            "443": "https",
            "445": "smb",
            "3306": "mysql",
            "3389": "rdp",
            "8080": "http-alt"
        }

        return port_map.get(str(port), f"service-{port}")

    def _format_openvas_vulnerabilities(self, vulnerabilities):
        """Format OpenVAS vulnerabilities to match expected output format"""
        formatted_vulns = {}

        for vuln in vulnerabilities:
            port = vuln.get("port", "0").split("/")[0] if "/" in vuln.get("port", "0") else vuln.get("port", "0")
            port = port.strip()

            if port not in formatted_vulns:
                service = self._guess_service_from_port(port)
                formatted_vulns[port] = {
                    "service": service,
                    "vulnerabilities": []
                }

            formatted_vulns[port]["vulnerabilities"].append({
                "script": vuln.get("name", "Unknown"),
                "output": vuln.get("description", ""),
                "severity": vuln.get("severity", "Medium")
            })

        return formatted_vulns

    def _basic_port_scan(self, target, ports=None):
        """
        Basic TCP port scanner as fallback when OpenVAS isn't available

        Args:
            target: Target IP or hostname
            ports: Optional list of ports to scan

        Returns:
            Basic scan results
        """
        self.update_status(f"Starting basic port scan on {target}", "info")
        self.update_progress(10)

        import socket
        import concurrent.futures

        # Use common ports if none specified
        if not ports:
            ports = [21, 22, 23, 25, 53, 80, 443, 445, 3306, 3389, 8080, 8443]

        results = {target: {}}

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = {}

            for port in ports:
                futures[executor.submit(self._check_port, target, port)] = port

            completed = 0
            for future in concurrent.futures.as_completed(futures):
                completed += 1
                progress = 10 + int(completed / len(ports) * 80)
                self.update_progress(progress)

                port = futures[future]
                is_open, banner = future.result()

                if is_open:
                    service = self._guess_service_from_port(port)
                    results[target][str(port)] = {
                        "service": service,
                        "product": banner if banner else "unknown",
                        "version": "unknown",
                        "script_results": {}
                    }

                    self.update_status(f"Found open port {port} ({service}) on {target}", "info")

        self.update_progress(100)
        self.update_status(f"Basic port scan completed. Found {len(results[target])} open ports.", "success")

        return results

    def _check_port(self, target, port):
        """Check if a port is open and try to grab a banner"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((target, int(port)))

            banner = ""
            if result == 0:
                try:
                    # Try to grab a banner
                    sock.settimeout(3)
                    sock.send(b"\r\n")
                    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                except:
                    pass
                finally:
                    sock.close()
                return True, banner

            sock.close()
        except:
            pass

        return False, ""

    def scan_host(self, target, ports=None):
        """
        Legacy method for compatibility - scan a single host

        Args:
            target: Target to scan
            ports: Optional list of ports (not used with OpenVAS)

        Returns:
            Scan results in the expected format
        """
        # Use OpenVAS if available
        if self.openvas_available:
            openvas_results = self.run_openvas_scan(target)

            # Check if scan succeeded
            if "error" not in openvas_results:
                return openvas_results

        # Fall back to basic scanning
        self.update_status("OpenVAS not available. Using basic port scanning.", "warning")
        return self._basic_port_scan(target, ports)

    def analyze_vulnerabilities(self, scan_results):
        """
        Legacy method for compatibility - extract vulnerabilities from scan results

        Args:
            scan_results: Results from scan_host method

        Returns:
            Vulnerabilities in the expected format
        """
        # Handle OpenVAS results
        if isinstance(scan_results, dict) and "scan_results" in scan_results:
            # Results are already in the expected format
            vulnerabilities = {}

            for host_result in scan_results.get("scan_results", []):
                host = host_result.get("host", "unknown")
                vulnerabilities[host] = host_result.get("vulnerabilities", {})

            return vulnerabilities

        # Basic scan results format
        vulnerabilities = {}

        for host, ports in scan_results.items():
            vulnerabilities[host] = {}

            for port, details in ports.items():
                vulnerabilities[host][port] = {
                    "service": details.get("service", "unknown"),
                    "vulnerabilities": []
                }

                # Add basic information as a "finding"
                vulnerabilities[host][port]["vulnerabilities"].append({
                    "script": "Port Discovery",
                    "output": f"Open port {port} ({details.get('service', 'unknown')})",
                    "severity": "Info"
                })

        return vulnerabilities

    def perform_comprehensive_scan(self, target, scan_type="both"):
        """
        Perform a comprehensive scan on a target

        Args:
            target: Target IP, hostname, or network range
            scan_type: Type of scan (system, network, or both)

        Returns:
            Scan results in the expected format
        """
        self.update_status(f"Starting {scan_type} vulnerability scan on {target}", "info")

        # Use OpenVAS if available
        if self.openvas_available:
            # Use fast scan for network, full scan for system or both
            openvas_scan_type = "fast" if scan_type == "network" else "full"
            results = self.run_openvas_scan(target, openvas_scan_type)

            # Check if scan succeeded
            if "error" not in results:
                # Save results
                self._save_results(results)
                return results

        # Fall back to basic scanning
        self.update_status("OpenVAS scan failed or not available. Using basic port scanning.", "warning")
        scan_results = self._basic_port_scan(target)

        # Format results to match expected structure
        results = {
            "scan_results": [{
                "host": target,
                "os_type": "unknown",
                "vulnerabilities": {},
                "services": {}
            }],
            "summary": {
                "target": target,
                "scan_type": scan_type,
                "vulnerabilities_found": 0,
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "scanner": "Basic Scanner"
            }
        }

        # Extract services from port scan
        services = {}
        for port, details in scan_results.get(target, {}).items():
            service_name = details.get("service", "unknown")
            services[service_name] = int(port)

            # Add each port as a section in vulnerabilities
            results["scan_results"][0]["vulnerabilities"][port] = {
                "service": service_name,
                "vulnerabilities": [{
                    "script": "Port Discovery",
                    "output": f"Open port {port} ({service_name})",
                    "severity": "Info"
                }]
            }

        results["scan_results"][0]["services"] = services
        results["summary"]["vulnerabilities_found"] = len(scan_results.get(target, {}))

        # Save results
        self._save_results(results)

        return results

    def _save_results(self, results):
        """Save scan results to a JSON file"""
        try:
            results_file = self.workspace / f'vuln_scan_{time.strftime("%Y%m%d_%H%M%S")}.json'
            with open(results_file, 'w') as f:
                json.dump(results, f, indent=4)
            self.update_status(f"Results saved to {results_file}", "info")
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
    scanner = OpenVASScanner("./test_workspace")
    scanner.add_progress_callback(print_progress)
    scanner.add_status_callback(print_status)

    # Configure OpenVAS if needed
    # scanner.configure_openvas("localhost", 9390, "admin", "admin")

    # Test on localhost or specified target
    target = "127.0.0.1"
    if len(sys.argv) > 1:
        target = sys.argv[1]

    print(f"Scanning target: {target}")
    results = scanner.perform_comprehensive_scan(target, "both")
    print(json.dumps(results, indent=2))