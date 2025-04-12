import argparse
import json
import logging
import os
import sys
from pathlib import Path
from typing import Dict, List, Optional
import time

# Import project modules
from reconnaissance import InformationGathering
from scanning import Scanning
from caldera_exploitation import CalderaExploitation
from attack_modules import IntegratedAttackPlanner, SystemAttackModule, NetworkServiceAttackModule
from test_openaiAPI import OpenAIGuide


class PenetrationTestOrchestrator:
    """Main orchestrator for the penetration testing framework"""

    def __init__(self,
                 target_network: str,
                 openai_api_key: str,
                 caldera_api_url: str,
                 caldera_api_key: str,
                 workspace: str = "./workspace"):
        """
        Initialize the penetration test orchestrator

        Args:
            target_network: Target network range in CIDR notation or IP address
            openai_api_key: OpenAI API key for AI guidance
            caldera_api_url: URL for the Caldera API
            caldera_api_key: API key for Caldera authentication
            workspace: Directory to store results and logs
        """
        self.target_network = target_network
        self.openai_api_key = openai_api_key
        self.caldera_api_url = caldera_api_url
        self.caldera_api_key = caldera_api_key

        # Setup workspace
        self.workspace = Path(workspace)
        self.workspace.mkdir(exist_ok=True)
        self._setup_logging()

        # Initialize modules
        self.reconnaissance = InformationGathering()
        self.scanning = Scanning()
        self.ai_guide = OpenAIGuide(openai_api_key)
        self.attack_planner = IntegratedAttackPlanner(workspace)
        self.exploitation = CalderaExploitation(caldera_api_url, caldera_api_key, workspace)

        self.logger.info(f"Initialized penetration test orchestrator targeting {target_network}")

    def _setup_logging(self):
        """Setup logging configuration"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.StreamHandler(sys.stdout),
                logging.FileHandler(self.workspace / 'orchestrator.log')
            ]
        )
        self.logger = logging.getLogger(__name__)

    def run_full_pentest(self, target_type: str = "network", attack_type: Optional[str] = None) -> Dict:
        """
        Execute a full penetration test workflow

        Args:
            target_type: Type of target - "system" or "network"
            attack_type: Type of attacks to focus on - "system", "network", or None for both

        Returns:
            Dictionary containing results from all phases
        """
        results = {
            'target_network': self.target_network,
            'target_type': target_type,
            'attack_type': attack_type if attack_type else "all",
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'phases': {}
        }

        try:
            # Phase 1: Information Gathering
            self.logger.info("=== Starting Information Gathering Phase ===")

            # Adjust target formatting for system vs network
            reconnaissance_target = self.target_network
            if target_type == "system" and "/" not in self.target_network:
                # For a system target without CIDR, add /32
                reconnaissance_target = f"{self.target_network}/32"

            recon_results = self.reconnaissance.gather_information(reconnaissance_target)
            results['phases']['information_gathering'] = recon_results
            self._save_phase_results('information_gathering', recon_results)
            self.logger.info(
                f"Information gathering completed. Found {len(recon_results.get('network_summary', {}).get('live_hosts', []))} live hosts.")

            # Get AI guidance for scanning phase
            scan_guidance = self.ai_guide.ask_guidance(recon_results)
            results['phases']['ai_guidance_scanning'] = scan_guidance
            self.logger.info(f"Received AI guidance for scanning phase")

            # Phase 2: Vulnerability Scanning
            self.logger.info("=== Starting Vulnerability Scanning Phase ===")
            scan_results = self._run_scanning_phase(recon_results, target_type)
            results['phases']['vulnerability_scanning'] = scan_results
            self._save_phase_results('vulnerability_scanning', scan_results)
            self.logger.info(f"Vulnerability scanning completed.")

            # Generate attack plan
            self.logger.info("=== Generating Attack Plan ===")
            attack_plan = self.attack_planner.generate_attack_plan(scan_results)
            results['phases']['attack_plan'] = attack_plan
            self._save_phase_results('attack_plan', attack_plan)
            self.logger.info(
                f"Attack plan generated with {len(attack_plan.get('top_recommendations', []))} top recommendations.")

            # Filter attack plan based on attack type if specified
            if attack_type == "system":
                # Focus on system attacks only
                attack_plan['network_attacks'] = []
                # Filter top recommendations
                attack_plan['top_recommendations'] = [
                    rec for rec in attack_plan.get('top_recommendations', [])
                    if rec.get('category', '') == 'system'
                ]
            elif attack_type == "network":
                # Focus on network attacks only
                attack_plan['system_attacks'] = []
                # Filter top recommendations
                attack_plan['top_recommendations'] = [
                    rec for rec in attack_plan.get('top_recommendations', [])
                    if rec.get('category', '') == 'network'
                ]

            # Get AI guidance for exploitation phase
            exploit_guidance = self.ai_guide.analyze_phase_results(
                "vulnerability_scanning",
                scan_results,
                "exploitation"
            )
            results['phases']['ai_guidance_exploitation'] = exploit_guidance
            self.logger.info(f"Received AI guidance for exploitation phase")

            # Phase 3: Exploitation with Caldera
            self.logger.info("=== Starting Exploitation Phase ===")
            # Check if Caldera API is accessible
            if self.exploitation.test_connection():
                # Prepare recommendations for Caldera
                caldera_recommendations = self._map_recommendations_to_caldera(attack_plan['top_recommendations'])
                exploitation_results = self.exploitation.execute_exploitation_phase(scan_results,
                                                                                    caldera_recommendations)
                results['phases']['exploitation'] = exploitation_results
                self._save_phase_results('exploitation', exploitation_results)
                self.logger.info(
                    f"Exploitation phase completed with {len(exploitation_results.get('successful_exploits', []))} successful exploits.")
            else:
                self.logger.error("Failed to connect to Caldera API. Skipping exploitation phase.")
                results['phases']['exploitation'] = {'error': 'Failed to connect to Caldera API'}

            # Generate final report
            self.logger.info("=== Generating Final Report ===")
            report = self._generate_report(results)
            results['final_report'] = report
            self._save_phase_results('final_report', report)
            self.logger.info("Penetration test completed successfully.")

            return results

        except Exception as e:
            self.logger.error(f"Error during penetration test: {str(e)}")
            results['error'] = str(e)
            return results

    def _run_scanning_phase(self, recon_results: Dict, target_type: str) -> Dict:
        """
        Execute vulnerability scanning phase based on reconnaissance results

        Args:
            recon_results: Results from information gathering phase
            target_type: Type of target - "system" or "network"

        Returns:
            Scan results dictionary
        """
        scan_results = {
            'scan_results': []
        }

        if target_type == "system":
            # For system targets, scan the specific IP
            host = self.target_network.split('/')[0]  # Remove CIDR notation if present

            # Get list of common ports to scan
            ports = [21, 22, 23, 25, 53, 80, 443, 445, 3389, 8080]

            # Perform vulnerability scan
            self.logger.info(f"Scanning host {host} on common ports")
            host_scan = self.scanning.scan_host(host, ports)

            # Analyze vulnerabilities
            vuln_results = self.scanning.analyze_vulnerabilities(host_scan)

            # Determine OS type from reconnaissance results or scan
            os_info = "unknown"
            if host in recon_results.get("host_details", {}):
                os_info = recon_results["host_details"][host].get("os", "unknown").lower()

            os_type = "unknown"
            if "windows" in os_info:
                os_type = "windows"
            elif "linux" in os_info:
                os_type = "linux"

            # Extract services
            services = {}
            for port, details in host_scan.get(host, {}).items():
                if isinstance(details, dict):
                    service_name = details.get("name", "unknown")
                    services[service_name] = int(port)

            # Add to scan results
            scan_results['scan_results'].append({
                'host': host,
                'os_type': os_type,
                'os_version': os_info,
                'services': services,
                'vulnerabilities': vuln_results.get(host, {})
            })

        else:  # Network scan
            # Get list of hosts from reconnaissance
            hosts = recon_results.get("network_summary", {}).get("live_hosts", [])
            host_details = recon_results.get("host_details", {})

            for host in hosts:
                # Get list of open ports from recon results
                ports = host_details.get(host, {}).get("open_ports", [])

                if not ports:
                    # If no ports found, use common ports
                    ports = [21, 22, 23, 25, 53, 80, 443, 445, 3389, 8080]

                # Perform vulnerability scan
                self.logger.info(f"Scanning host {host} on {len(ports)} ports")
                host_scan = self.scanning.scan_host(host, ports)

                # Analyze vulnerabilities
                vuln_results = self.scanning.analyze_vulnerabilities(host_scan)

                # Determine OS type based on recon results
                os_info = host_details.get(host, {}).get("os", "unknown").lower()
                os_type = "unknown"
                if "windows" in os_info:
                    os_type = "windows"
                elif "linux" in os_info:
                    os_type = "linux"

                # Extract services
                services = {}
                for port, details in host_scan.get(host, {}).items():
                    if isinstance(details, dict):
                        service_name = details.get("name", "unknown")
                        services[service_name] = int(port)

                # Add to scan results
                scan_results['scan_results'].append({
                    'host': host,
                    'os_type': os_type,
                    'os_version': os_info,
                    'services': services,
                    'vulnerabilities': vuln_results.get(host, {})
                })

        return scan_results

    def _map_recommendations_to_caldera(self, recommendations: List[Dict]) -> List[Dict]:
        """
        Map attack recommendations to Caldera abilities

        Args:
            recommendations: List of attack recommendations

        Returns:
            List of recommendations formatted for Caldera
        """
        caldera_recommendations = []

        for rec in recommendations:
            details = rec.get('details', {})
            caldera_recommendations.append({
                'technique_id': details.get('technique_id', ''),
                'name': details.get('name', ''),
                'tool': 'caldera',
                'commands': [],  # Caldera doesn't need specific commands
                'reason': details.get('reason', '')
            })

        return caldera_recommendations

    def _generate_report(self, results: Dict) -> Dict:
        """
        Generate a final penetration test report

        Args:
            results: Combined results from all phases

        Returns:
            Report dictionary
        """
        # Extract key findings
        recon_results = results.get('phases', {}).get('information_gathering', {})
        scan_results = results.get('phases', {}).get('vulnerability_scanning', {})
        exploitation_results = results.get('phases', {}).get('exploitation', {})

        # Count hosts, vulnerabilities, and successful exploits
        host_count = len(recon_results.get('network_summary', {}).get('live_hosts', []))

        vuln_count = 0
        critical_vulns = 0
        for target in scan_results.get('scan_results', []):
            for port, vuln_details in target.get('vulnerabilities', {}).items():
                vuln_list = vuln_details.get('vulnerabilities', [])
                vuln_count += len(vuln_list)

                # Count critical vulnerabilities (simplified criteria)
                for vuln in vuln_list:
                    if 'critical' in vuln.get('output', '').lower() or 'high' in vuln.get('output', '').lower():
                        critical_vulns += 1

        successful_exploits = len(exploitation_results.get('successful_exploits', []))

        # Generate report
        report = {
            'summary': {
                'target_network': self.target_network,
                'target_type': results.get('target_type', 'network'),
                'attack_focus': results.get('attack_type', 'all'),
                'hosts_discovered': host_count,
                'vulnerabilities_found': vuln_count,
                'critical_vulnerabilities': critical_vulns,
                'successful_exploits': successful_exploits
            },
            'key_findings': [],
            'recommendations': []
        }

        # Add key findings
        if critical_vulns > 0:
            report['key_findings'].append({
                'title': 'Critical Vulnerabilities Detected',
                'description': f'Found {critical_vulns} critical vulnerabilities that should be addressed immediately.'
            })

        if successful_exploits > 0:
            report['key_findings'].append({
                'title': 'Successful System Compromise',
                'description': f'Successfully compromised {successful_exploits} systems during the penetration test.'
            })

        # Add attack type specific findings
        target_type = results.get('target_type', 'network')
        attack_type = results.get('attack_type', 'all')

        if target_type == "system":
            report['key_findings'].append({
                'title': 'System-Focused Assessment',
                'description': f'Targeted assessment conducted on individual system {self.target_network}'
            })
        else:
            report['key_findings'].append({
                'title': 'Network-Wide Assessment',
                'description': f'Assessment conducted across network range {self.target_network}'
            })

        if attack_type == "system":
            report['key_findings'].append({
                'title': 'System Attack Focus',
                'description': 'Assessment focused on system-level attacks including authentication, authorization, and code execution vectors'
            })
        elif attack_type == "network":
            report['key_findings'].append({
                'title': 'Network Service Focus',
                'description': 'Assessment focused on network service attacks against SSH, FTP, SMB, HTTP, and RDP services'
            })

        # Add default recommendations
        report['recommendations'] = [
            {
                'title': 'Patch Vulnerable Systems',
                'description': 'Apply security patches to all systems with identified vulnerabilities.'
            },
            {
                'title': 'Implement Network Segmentation',
                'description': 'Segment the network to limit lateral movement in case of compromise.'
            },
            {
                'title': 'Strengthen Authentication',
                'description': 'Implement multi-factor authentication and strong password policies.'
            }
        ]

        # Add specific recommendations based on attack type
        if attack_type == "system" or attack_type == "all":
            report['recommendations'].append({
                'title': 'Implement Least Privilege',
                'description': 'Ensure all users and services operate with the minimum necessary privileges.'
            })

        if attack_type == "network" or attack_type == "all":
            report['recommendations'].append({
                'title': 'Secure Network Services',
                'description': 'Disable unnecessary services and secure required services with strong configurations.'
            })

        return report

    def _save_phase_results(self, phase_name: str, results: Dict):
        """Save results from a specific phase"""
        try:
            with open(self.workspace / f'{phase_name}_results.json', 'w') as f:
                json.dump(results, f, indent=4)
                self.logger.info(f"Saved {phase_name} results to file")
        except Exception as e:
            self.logger.error(f"Failed to save {phase_name} results: {str(e)}")


def main():
    """Main entry point for the penetration testing framework"""
    parser = argparse.ArgumentParser(description='Run automated penetration tests')
    parser.add_argument('--target', required=True, help='Target network range in CIDR notation or single IP address')
    parser.add_argument('--target-type', choices=['system', 'network'], default='network',
                        help='Type of target (system or network)')
    parser.add_argument('--attack-type', choices=['system', 'network', 'all'], default='all',
                        help='Type of attacks to focus on')
    parser.add_argument('--openai-key', required=True, help='OpenAI API key')
    parser.add_argument('--caldera-url', default='http://localhost:8888', help='Caldera API URL')
    parser.add_argument('--caldera-key', default='ADMIN123', help='Caldera API key')
    parser.add_argument('--workspace', default='./workspace', help='Workspace directory for results')

    args = parser.parse_args()

    # Create orchestrator
    orchestrator = PenetrationTestOrchestrator(
        target_network=args.target,
        openai_api_key=args.openai_key,
        caldera_api_url=args.caldera_url,
        caldera_api_key=args.caldera_key,
        workspace=args.workspace
    )

    # Run penetration test with specified target and attack types
    attack_type = None if args.attack_type == 'all' else args.attack_type
    results = orchestrator.run_full_pentest(target_type=args.target_type, attack_type=attack_type)

    # Save final results
    with open(os.path.join(args.workspace, 'final_results.json'), 'w') as f:
        json.dump(results, f, indent=4)

    print(f"Penetration test completed. Results saved to {args.workspace}/final_results.json")


if __name__ == "__main__":
    main()