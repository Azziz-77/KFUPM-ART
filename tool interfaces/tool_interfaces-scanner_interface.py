import os
import re
import json
import time
import logging
import subprocess
from typing import Dict, List, Optional, Union, Any

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class ScannerInterface:
    """
    Interface to interact with scanning tools like nmap, gobuster, nikto, etc.
    """

    def __init__(self, workspace: str = "./workspace"):
        """
        Initialize the Scanner interface.

        Args:
            workspace: Directory to store scan results
        """
        self.workspace = workspace

        # Create workspace directory if it doesn't exist
        os.makedirs(self.workspace, exist_ok=True)

        # Check if nmap is installed
        try:
            subprocess.run(["nmap", "--version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
            logger.info("Nmap is installed and available")
        except (subprocess.SubprocessError, FileNotFoundError):
            logger.warning("Nmap is not installed or not in PATH")

    def execute_command(self, command: str) -> str:
        """
        Execute a scanning command and return the result.

        Args:
            command: The command to execute

        Returns:
            The command output
        """
        try:
            # Parse the command to determine which scanner to use
            scanner_type = self._determine_scanner_type(command)

            if scanner_type == "nmap":
                return self._run_nmap(command)
            elif scanner_type == "gobuster":
                return self._run_gobuster(command)
            elif scanner_type == "nikto":
                return self._run_nikto(command)
            elif scanner_type == "dirb":
                return self._run_dirb(command)
            elif scanner_type == "wpscan":
                return self._run_wpscan(command)
            elif scanner_type == "xray":
                return self._run_xray(command)
            else:
                # Default to just running the command directly
                return self._run_raw_command(command)

        except Exception as e:
            error_msg = f"Error executing scanning command: {str(e)}"
            logger.error(error_msg)
            return f"Error: {error_msg}"

    def _determine_scanner_type(self, command: str) -> str:
        """
        Determine the scanner type from the command.

        Args:
            command: The command to parse

        Returns:
            The scanner type (nmap, gobuster, etc.)
        """
        command_lower = command.lower()

        if command_lower.startswith("nmap"):
            return "nmap"
        elif command_lower.startswith("gobuster"):
            return "gobuster"
        elif command_lower.startswith("nikto"):
            return "nikto"
        elif command_lower.startswith("dirb"):
            return "dirb"
        elif command_lower.startswith("wpscan"):
            return "wpscan"
        elif command_lower.startswith("xray"):
            return "xray"
        else:
            return "unknown"

    def _run_raw_command(self, command: str) -> str:
        """
        Run a raw command and return the output.

        Args:
            command: The command to run

        Returns:
            The command output
        """
        try:
            # Run the command
            process = subprocess.run(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            # Combine stdout and stderr
            output = process.stdout
            if process.stderr:
                output += "\n" + process.stderr

            return output

        except Exception as e:
            return f"Error running command: {str(e)}"

    def _run_nmap(self, command: str) -> str:
        """
        Run an nmap scan and return the results.

        Args:
            command: The nmap command to run

        Returns:
            The scan results
        """
        try:
            # Extract target from command
            target_match = re.search(r'(?:^|\s)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?|\S+\.\S+)(?:\s|$)',
                                     command)
            target = target_match.group(1) if target_match else "unknown"

            # Generate output filename
            output_file = os.path.join(self.workspace, f"nmap_scan_{target}_{int(time.time())}.xml")

            # Add -oX option to command if not already present
            if "-oX" not in command and "-oA" not in command:
                command += f" -oX {output_file}"

            # Run the command
            logger.info(f"Running nmap scan: {command}")
            process = subprocess.run(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            # Combine stdout and stderr
            output = process.stdout
            if process.stderr:
                output += "\n" + process.stderr

            # Check if output file was created
            if os.path.exists(output_file):
                output += f"\n\nScan results saved to: {output_file}"

            return output

        except Exception as e:
            return f"Error running nmap scan: {str(e)}"

    def _run_gobuster(self, command: str) -> str:
        """Run a gobuster scan."""
        return self._run_raw_command(command)

    def _run_nikto(self, command: str) -> str:
        """Run a nikto scan."""
        return self._run_raw_command(command)

    def _run_dirb(self, command: str) -> str:
        """Run a dirb scan."""
        return self._run_raw_command(command)

    def _run_wpscan(self, command: str) -> str:
        """Run a wpscan scan."""
        return self._run_raw_command(command)

    def _run_xray(self, command: str) -> str:
        """Run a xray scan."""
        return self._run_raw_command(command)

    def parse_nmap_results(self, xml_file: str) -> Dict[str, Any]:
        """
        Parse nmap XML results.

        Args:
            xml_file: Path to the XML file

        Returns:
            Dictionary with parsed results
        """
        try:
            # Check if python-libnmap is installed
            try:
                from libnmap.parser import NmapParser

                # Parse the XML file
                report = NmapParser.parse_fromfile(xml_file)

                # Create result dictionary
                result = {
                    "scan_info": {
                        "command": report.commandline,
                        "version": report.version,
                        "scan_type": report.scan_type,
                        "started": report.started,
                        "completed": report.endtime
                    },
                    "hosts": []
                }

                # Add hosts
                for host in report.hosts:
                    host_info = {
                        "ip": host.address,
                        "status": host.status,
                        "hostnames": [hostname.name for hostname in host.hostnames],
                        "ports": []
                    }

                    # Add ports
                    for port in host.get_open_ports():
                        service = host.get_service(port[0], port[1])
                        port_info = {
                            "port": port[0],
                            "protocol": port[1],
                            "service": service.service,
                            "state": service.state,
                            "banner": service.banner
                        }
                        host_info["ports"].append(port_info)

                    result["hosts"].append(host_info)

                return result

            except ImportError:
                logger.warning("python-libnmap not installed, using basic XML parsing")

                # Use basic XML parsing
                import xml.etree.ElementTree as ET
                tree = ET.parse(xml_file)
                root = tree.getroot()

                # Create result dictionary
                result = {
                    "scan_info": {
                        "command": root.get("args", ""),
                        "version": root.get("version", ""),
                        "scan_type": "",
                        "started": root.get("start", ""),
                        "completed": root.get("end", "")
                    },
                    "hosts": []
                }

                # Add hosts
                for host in root.findall(".//host"):
                    address = host.find(".//address")
                    status = host.find(".//status")

                    host_info = {
                        "ip": address.get("addr") if address is not None else "",
                        "status": status.get("state") if status is not None else "",
                        "hostnames": [],
                        "ports": []
                    }

                    # Add hostnames
                    for hostname in host.findall(".//hostname"):
                        host_info["hostnames"].append(hostname.get("name", ""))

                    # Add ports
                    for port in host.findall(".//port"):
                        service = port.find(".//service")

                        port_info = {
                            "port": port.get("portid", ""),
                            "protocol": port.get("protocol", ""),
                            "service": service.get("name", "") if service is not None else "",
                            "state": port.find(".//state").get("state", "") if port.find(
                                ".//state") is not None else "",
                            "banner": ""
                        }

                        host_info["ports"].append(port_info)

                    result["hosts"].append(host_info)

                return result

        except Exception as e:
            logger.error(f"Error parsing nmap results: {str(e)}")
            return {"error": str(e)}