import nmap
import logging
import json
from pathlib import Path
import sys


class InformationGathering:
    def __init__(self, workspace: str = "./workspace"):
        """
        Initialize the reconnaissance module
        Args:
            workspace: Directory to store results and logs
        """
        self.nmap_scanner = nmap.PortScanner()
        self.workspace = Path(workspace)
        self.workspace.mkdir(exist_ok=True)
        self._setup_logging()

    def _setup_logging(self):
        """Setup logging configuration"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(self.workspace / 'reconnaissance.log'),
                logging.StreamHandler(sys.stdout)  # Add console output
            ]
        )
        self.logger = logging.getLogger(__name__)

    def perform_host_discovery(self, target_network: str):
        """Perform host discovery with simpler approach"""
        self.logger.info(f"Starting host discovery on {target_network}")
        live_hosts = []

        try:
            # For a single IP target (system mode), just verify it's reachable
            if '/' not in target_network or target_network.endswith('/32'):
                # Extract the IP address without CIDR
                ip = target_network.split('/')[0]
                self.logger.info(f"System mode: checking if {ip} is reachable")

                # Simple ping scan on the single IP
                self.nmap_scanner.scan(hosts=ip, arguments='-sn -T4')

                if ip in self.nmap_scanner.all_hosts():
                    if self.nmap_scanner[ip].state() == 'up':
                        live_hosts.append(ip)
                        self.logger.info(f"Host {ip} is up")
                    else:
                        self.logger.info(f"Host {ip} appears to be down, but adding it anyway for scanning")
                        live_hosts.append(ip)  # Add it anyway for scanning
                else:
                    self.logger.info(f"Host {ip} not found in scan results, adding it anyway for scanning")
                    live_hosts.append(ip)  # Add it anyway for scanning

            # For network scan
            else:
                self.nmap_scanner.scan(hosts=target_network, arguments='-sn -T4')

                for host in self.nmap_scanner.all_hosts():
                    if self.nmap_scanner[host].state() == 'up':
                        live_hosts.append(host)
                        self.logger.info(f"Discovered live host: {host}")

        except Exception as e:
            self.logger.error(f"Error in host discovery: {str(e)}")
            # If there's an error in system mode, still add the target
            if '/' not in target_network or target_network.endswith('/32'):
                ip = target_network.split('/')[0]
                live_hosts.append(ip)
                self.logger.info(f"Added {ip} despite error")

        self.logger.info(f"Found {len(live_hosts)} live hosts")
        return live_hosts

    def perform_service_detection(self, target: str):
        """Perform basic service detection"""
        self.logger.info(f"Starting service detection on {target}")
        services = {}

        try:
            # Fast service scan with common ports
            common_ports = "21-25,53,80,443,445,3306,3389,8080,8443"
            self.nmap_scanner.scan(hosts=target, arguments=f'-sV -p{common_ports} -T4')

            if target in self.nmap_scanner.all_hosts():
                self.logger.info(f"Service scan completed for {target}")

                for proto in self.nmap_scanner[target].all_protocols():
                    self.logger.info(f"Protocol: {proto}")

                    ports = self.nmap_scanner[target][proto].keys()
                    for port in ports:
                        self.logger.info(f"Found port {port} on {target}")
                        service_info = self.nmap_scanner[target][proto][port]

                        services[str(port)] = {  # Convert port to string for JSON serialization
                            'name': service_info.get('name', 'unknown'),
                            'product': service_info.get('product', 'unknown'),
                            'version': service_info.get('version', 'unknown')
                        }

                        self.logger.info(f"Port {port}: {services[str(port)]}")
            else:
                self.logger.warning(f"Target {target} not found in scan results")

        except Exception as e:
            self.logger.error(f"Error in service detection for {target}: {str(e)}")

        return services

    def gather_information(self, target_network: str):
        """Main method to gather information"""
        self.logger.info(f"Starting reconnaissance on {target_network}")

        try:
            # Get live hosts
            live_hosts = self.perform_host_discovery(target_network)

            # Process each host - limit to first 8 hosts for speed
            host_details = {}
            max_hosts = 1 if ('/' not in target_network or target_network.endswith('/32')) else 8

            for host in live_hosts[:max_hosts]:
                self.logger.info(f"Processing host details for {host}")

                # Detect services
                services = self.perform_service_detection(host)

                # Get open ports
                open_ports = list(services.keys())
                self.logger.info(f"Open ports for {host}: {open_ports}")

                # Try basic OS detection
                os_info = "Unknown"
                try:
                    self.nmap_scanner.scan(host, arguments="-O --osscan-limit -T4")
                    os_matches = self.nmap_scanner[host].get("osmatch", [])
                    if os_matches and len(os_matches) > 0:
                        os_info = os_matches[0].get("name", "Unknown")
                        self.logger.info(f"OS detection for {host}: {os_info}")
                except Exception as e:
                    self.logger.error(f"OS detection failed for {host}: {str(e)}")

                # Store host details
                host_details[host] = {
                    "open_ports": open_ports,
                    "os": os_info,
                    "services": services
                }

                self.logger.info(f"Host details for {host}: {json.dumps(host_details[host], indent=2)}")

            # Create result structure with correct format
            results = {
                "phase": "Information Gathering",
                "network_summary": {
                    "target_network": target_network,
                    "live_hosts": live_hosts
                },
                "host_details": host_details,
                "actionable_insights": {
                    "next_step": "Vulnerability Scanning",
                    "high_priority_hosts": [
                        host for host, details in host_details.items()
                        if any(int(port) in [80, 443, 22, 3389] for port in details.get("open_ports", []))
                    ]
                }
            }

            # Save results
            try:
                results_file = self.workspace / 'recon_results.json'
                with open(results_file, 'w') as f:
                    json.dump(results, f, indent=4)
                self.logger.info(f"Results saved to {results_file}")
            except Exception as e:
                self.logger.error(f"Error saving results: {str(e)}")

            return results

        except Exception as e:
            self.logger.error(f"Error in reconnaissance: {str(e)}")
            # Return minimal results
            return {
                "phase": "Information Gathering",
                "network_summary": {
                    "target_network": target_network,
                    "live_hosts": [target_network.split('/')[0]]  # At least include the target
                },
                "host_details": {},
                "actionable_insights": {
                    "next_step": "Vulnerability Scanning",
                    "high_priority_hosts": []
                }
            }


# For standalone testing
if __name__ == "__main__":
    recon = InformationGathering()

    # Test with system target
    target_system = "192.168.1.153"
    print(f"\nTesting with system target: {target_system}")
    system_results = recon.gather_information(target_system)
    print(json.dumps(system_results, indent=2))

    # Test with network target
    target_network = "192.168.1.0/24"
    print(f"\nTesting with network target: {target_network}")
    network_results = recon.gather_information(target_network)
    print(json.dumps(network_results, indent=2))