"""
Enhanced Nmap XML Parser for more effective vulnerability analysis.
"""
import xml.etree.ElementTree as ET
import logging
import re
import os
from typing import Dict, List, Any, Optional

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class NmapParser:
    """
    Enhanced parser for Nmap XML output with vulnerability detection capabilities.
    """

    def __init__(self):
        """Initialize the parser."""
        # Dictionary of known vulnerable service versions
        # Format: {service_name: [(version_regex, vulnerability_name, severity)]}
        self.vulnerable_versions = {
            'proftpd': [
                (r'1\.3\.5', 'ProFTPD 1.3.5 Mod_Copy Command Execution', 'high'),
                (r'1\.3\.[1-4]', 'ProFTPD Multiple Vulnerabilities', 'medium')
            ],
            'apache': [
                (r'2\.4\.7', 'Apache 2.4.7 Multiple Vulnerabilities', 'medium'),
                (r'2\.2\.[0-9]', 'Apache 2.2.x Multiple Vulnerabilities', 'medium')
            ],
            'openssh': [
                (r'6\.6\.1', 'OpenSSH 6.6.1 Information Disclosure', 'low')
            ],
            'mysql': [
                (r'5\.[0-6]', 'MySQL 5.x Multiple Vulnerabilities', 'medium')
            ],
            'samba': [
                (r'3\.X', 'Samba 3.X Multiple Vulnerabilities', 'medium'),
                (r'4\.X', 'Samba 4.X Multiple Vulnerabilities', 'medium')
            ]
        }

    def parse_nmap_xml(self, xml_file: str) -> Dict[str, Any]:
        """
        Parse Nmap XML output file.

        Args:
            xml_file: Path to the XML file

        Returns:
            Dictionary with parsed results and detected vulnerabilities
        """
        try:
            if not os.path.exists(xml_file):
                logger.error(f"XML file not found: {xml_file}")
                return {"error": "XML file not found"}

            tree = ET.parse(xml_file)
            root = tree.getroot()

            # Extract scan information
            scan_info = {
                "scan_time": root.get("start", ""),
                "args": root.get("args", ""),
                "hosts_total": len(root.findall(".//host")),
                "hosts_up": len(root.findall(".//host/status[@state='up']"))
            }

            # Extract host information
            hosts = []
            for host_elem in root.findall(".//host"):
                host = self._parse_host(host_elem)
                hosts.append(host)

            # Detect potential vulnerabilities
            for host in hosts:
                host["vulnerabilities"] = self._detect_vulnerabilities(host)

            return {
                "scan_info": scan_info,
                "hosts": hosts
            }

        except Exception as e:
            logger.error(f"Error parsing Nmap XML: {str(e)}")
            return {"error": str(e)}

    def _parse_host(self, host_elem: ET.Element) -> Dict[str, Any]:
        """
        Parse host element from Nmap XML.

        Args:
            host_elem: Host XML element

        Returns:
            Dictionary with host information
        """
        # Get IP address
        address = host_elem.find(".//address[@addrtype='ipv4']")
        ip = address.get("addr") if address is not None else ""

        # Get MAC address if available
        mac_elem = host_elem.find(".//address[@addrtype='mac']")
        mac = mac_elem.get("addr") if mac_elem is not None else ""
        mac_vendor = mac_elem.get("vendor") if mac_elem is not None else ""

        # Get hostname if available
        hostname = ""
        hostname_elem = host_elem.find(".//hostname")
        if hostname_elem is not None:
            hostname = hostname_elem.get("name", "")

        # Get OS detection results
        os_info = {}
        os_match = host_elem.find(".//osclass")
        if os_match is not None:
            os_info = {
                "type": os_match.get("type", ""),
                "vendor": os_match.get("vendor", ""),
                "osfamily": os_match.get("osfamily", ""),
                "osgen": os_match.get("osgen", "")
            }

        # Extract port/service information
        ports = []
        for port_elem in host_elem.findall(".//port"):
            port_info = self._parse_port(port_elem)
            if port_info:
                ports.append(port_info)

        return {
            "ip": ip,
            "mac": mac,
            "mac_vendor": mac_vendor,
            "hostname": hostname,
            "os_info": os_info,
            "ports": ports
        }

    def _parse_port(self, port_elem: ET.Element) -> Dict[str, str]:
        """
        Parse port element from Nmap XML.

        Args:
            port_elem: Port XML element

        Returns:
            Dictionary with port information
        """
        port_id = port_elem.get("portid", "")
        protocol = port_elem.get("protocol", "")

        # Get state information
        state_elem = port_elem.find("state")
        state = state_elem.get("state", "") if state_elem is not None else ""

        # Get service information
        service_elem = port_elem.find("service")
        service = {}
        if service_elem is not None:
            service = {
                "name": service_elem.get("name", ""),
                "product": service_elem.get("product", ""),
                "version": service_elem.get("version", ""),
                "extrainfo": service_elem.get("extrainfo", "")
            }

        return {
            "port": port_id,
            "protocol": protocol,
            "state": state,
            "service": service
        }

    def _detect_vulnerabilities(self, host: Dict[str, Any]) -> List[Dict[str, str]]:
        """
        Detect potential vulnerabilities based on service versions.

        Args:
            host: Host information dictionary

        Returns:
            List of potential vulnerabilities
        """
        vulnerabilities = []

        for port_info in host.get("ports", []):
            service = port_info.get("service", {})
            service_name = service.get("name", "").lower()
            product = service.get("product", "").lower()
            version = service.get("version", "")

            # If service name doesn't match known vulnerabilities, try the product name
            if service_name not in self.vulnerable_versions and product:
                for known_service in self.vulnerable_versions.keys():
                    if known_service in product:
                        service_name = known_service
                        break

            # Check for known vulnerabilities
            if service_name in self.vulnerable_versions:
                for version_regex, vuln_name, severity in self.vulnerable_versions[service_name]:
                    if version and re.search(version_regex, version, re.IGNORECASE):
                        vulnerabilities.append({
                            "service": service_name,
                            "port": port_info.get("port", ""),
                            "version": version,
                            "vulnerability": vuln_name,
                            "severity": severity
                        })

            # Check for common vulnerabilities by port
            if port_info.get("port") == "21" and service_name == "ftp" and "anonymous" in service.get("extrainfo",
                                                                                                      "").lower():
                vulnerabilities.append({
                    "service": "ftp",
                    "port": "21",
                    "version": version,
                    "vulnerability": "Anonymous FTP Access",
                    "severity": "medium"
                })

        return vulnerabilities

    def extract_metasploit_suggestions(self, vulnerabilities: List[Dict[str, str]]) -> List[Dict[str, str]]:
        """
        Generate suggested Metasploit modules based on detected vulnerabilities.

        Args:
            vulnerabilities: List of vulnerability dictionaries

        Returns:
            List of suggested Metasploit modules
        """
        suggestions = []

        # Map vulnerabilities to likely Metasploit modules
        vulnerability_to_module = {
            "ProFTPD 1.3.5 Mod_Copy Command Execution": {
                "module": "exploit/unix/ftp/proftpd_modcopy_exec",
                "description": "ProFTPD 1.3.5 Mod_Copy Command Execution"
            },
            "Apache 2.4.7 Multiple Vulnerabilities": {
                "module": "auxiliary/scanner/http/apache_optionsbleed",
                "description": "Apache Optionsbleed Scanner"
            },
            "Samba 3.X Multiple Vulnerabilities": {
                "module": "exploit/linux/samba/is_known_pipename",
                "description": "Samba is_known_pipename() Arbitrary Module Load"
            },
            "Anonymous FTP Access": {
                "module": "auxiliary/scanner/ftp/anonymous",
                "description": "Anonymous FTP Access Scanner"
            }
        }

        for vuln in vulnerabilities:
            vuln_name = vuln.get("vulnerability", "")
            if vuln_name in vulnerability_to_module:
                module_info = vulnerability_to_module[vuln_name]
                suggestions.append({
                    "vulnerability": vuln_name,
                    "service": vuln.get("service", ""),
                    "port": vuln.get("port", ""),
                    "module": module_info["module"],
                    "description": module_info["description"],
                    "severity": vuln.get("severity", "")
                })

        return suggestions


def parse_latest_nmap_scan(workspace_dir: str = "./workspace") -> Dict[str, Any]:
    """
    Find and parse the most recent Nmap XML scan result.

    Args:
        workspace_dir: Directory where scan results are stored

    Returns:
        Parsed scan results
    """
    try:
        # Find all XML files in the workspace directory
        xml_files = []
        for file in os.listdir(workspace_dir):
            if file.startswith("nmap_scan_") and file.endswith(".xml"):
                xml_files.append(os.path.join(workspace_dir, file))

        if not xml_files:
            logger.error(f"No Nmap XML files found in {workspace_dir}")
            return {"error": "No Nmap XML files found"}

        # Find the most recent file based on modification time
        latest_file = max(xml_files, key=os.path.getmtime)
        logger.info(f"Parsing most recent Nmap scan: {latest_file}")

        # Parse the XML file
        parser = NmapParser()
        scan_results = parser.parse_nmap_xml(latest_file)

        # Extract Metasploit suggestions
        if "hosts" in scan_results:
            for host in scan_results["hosts"]:
                host["metasploit_suggestions"] = parser.extract_metasploit_suggestions(
                    host.get("vulnerabilities", [])
                )

        return scan_results

    except Exception as e:
        logger.error(f"Error parsing latest Nmap scan: {str(e)}")
        return {"error": str(e)}