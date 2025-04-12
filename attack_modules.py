import logging
from typing import Dict, List, Optional
from pathlib import Path


class SystemAttackModule:
    """Module for system-focused attacks covering Windows and Linux"""

    def __init__(self, workspace: str = "./workspace"):
        """Initialize the system attack module"""
        self.workspace = Path(workspace)
        self.workspace.mkdir(exist_ok=True)
        self.logger = logging.getLogger(__name__)

    def authenticate_attacks(self, target: Dict, os_type: str) -> List[Dict]:
        """
        Generate authentication attack recommendations for the target

        Args:
            target: Target information including host and detected services
            os_type: Operating system type (windows/linux)

        Returns:
            List of authentication attack recommendations
        """
        attacks = []

        if os_type.lower() == "windows":
            attacks.extend([
                {
                    'technique_id': 'T1110.001',
                    'name': 'Password Guessing',
                    'tool': 'caldera',
                    'commands': [],
                    'reason': 'Attempt to guess common Windows credentials'
                },
                {
                    'technique_id': 'T1110.002',
                    'name': 'Password Cracking',
                    'tool': 'caldera',
                    'commands': [],
                    'reason': 'Attempt to crack Windows password hashes'
                },
                {
                    'technique_id': 'T1558.003',
                    'name': 'Kerberoasting',
                    'tool': 'caldera',
                    'commands': [],
                    'reason': 'Extract service account credentials from Active Directory'
                }
            ])
        elif os_type.lower() == "linux":
            attacks.extend([
                {
                    'technique_id': 'T1110.001',
                    'name': 'Password Guessing',
                    'tool': 'caldera',
                    'commands': [],
                    'reason': 'Attempt to guess common Linux credentials'
                },
                {
                    'technique_id': 'T1110.002',
                    'name': 'Password Cracking',
                    'tool': 'caldera',
                    'commands': [],
                    'reason': 'Attempt to crack Linux password hashes'
                },
                {
                    'technique_id': 'T1552.004',
                    'name': 'Private Keys',
                    'tool': 'caldera',
                    'commands': [],
                    'reason': 'Search for private keys on Linux systems'
                }
            ])

        return attacks

    def authorization_attacks(self, target: Dict, os_type: str) -> List[Dict]:
        """
        Generate authorization attack recommendations for the target

        Args:
            target: Target information including host and detected services
            os_type: Operating system type (windows/linux)

        Returns:
            List of authorization attack recommendations
        """
        attacks = []

        if os_type.lower() == "windows":
            attacks.extend([
                {
                    'technique_id': 'T1134',
                    'name': 'Access Token Manipulation',
                    'tool': 'caldera',
                    'commands': [],
                    'reason': 'Manipulate access tokens to elevate privileges'
                },
                {
                    'technique_id': 'T1548.002',
                    'name': 'Bypass User Account Control',
                    'tool': 'caldera',
                    'commands': [],
                    'reason': 'Bypass UAC to execute with elevated privileges'
                },
                {
                    'technique_id': 'T1574.002',
                    'name': 'DLL Side-Loading',
                    'tool': 'caldera',
                    'commands': [],
                    'reason': 'Load malicious DLL to elevate privileges'
                }
            ])
        elif os_type.lower() == "linux":
            attacks.extend([
                {
                    'technique_id': 'T1548.001',
                    'name': 'Setuid and Setgid',
                    'tool': 'caldera',
                    'commands': [],
                    'reason': 'Utilize setuid/setgid binaries to elevate privileges'
                },
                {
                    'technique_id': 'T1547.006',
                    'name': 'Linux Kernel Modules',
                    'tool': 'caldera',
                    'commands': [],
                    'reason': 'Load malicious kernel modules to gain root access'
                },
                {
                    'technique_id': 'T1068',
                    'name': 'Privilege Escalation via Vulnerability',
                    'tool': 'caldera',
                    'commands': [],
                    'reason': 'Exploit Linux kernel or service vulnerabilities'
                }
            ])

        return attacks

    def code_execution_attacks(self, target: Dict, os_type: str) -> List[Dict]:
        """
        Generate code execution attack recommendations for the target

        Args:
            target: Target information including host and detected services
            os_type: Operating system type (windows/linux)

        Returns:
            List of code execution attack recommendations
        """
        attacks = []

        if os_type.lower() == "windows":
            attacks.extend([
                {
                    'technique_id': 'T1059.001',
                    'name': 'PowerShell',
                    'tool': 'caldera',
                    'commands': [],
                    'reason': 'Execute malicious PowerShell commands'
                },
                {
                    'technique_id': 'T1053.005',
                    'name': 'Scheduled Task',
                    'tool': 'caldera',
                    'commands': [],
                    'reason': 'Create scheduled task to execute malicious code'
                },
                {
                    'technique_id': 'T1218.005',
                    'name': 'Mshta',
                    'tool': 'caldera',
                    'commands': [],
                    'reason': 'Use mshta.exe to execute malicious code'
                }
            ])
        elif os_type.lower() == "linux":
            attacks.extend([
                {
                    'technique_id': 'T1059.004',
                    'name': 'Unix Shell',
                    'tool': 'caldera',
                    'commands': [],
                    'reason': 'Execute malicious shell commands'
                },
                {
                    'technique_id': 'T1053.003',
                    'name': 'Cron',
                    'tool': 'caldera',
                    'commands': [],
                    'reason': 'Use cron jobs to execute malicious code'
                },
                {
                    'technique_id': 'T1059.006',
                    'name': 'Python',
                    'tool': 'caldera',
                    'commands': [],
                    'reason': 'Use Python to execute malicious code'
                }
            ])

        return attacks


class NetworkServiceAttackModule:
    """Module for network service-focused attacks"""

    def __init__(self, workspace: str = "./workspace"):
        """Initialize the network service attack module"""
        self.workspace = Path(workspace)
        self.workspace.mkdir(exist_ok=True)
        self.logger = logging.getLogger(__name__)

    def ssh_attacks(self, target: Dict) -> List[Dict]:
        """
        Generate SSH attack recommendations for the target

        Args:
            target: Target information including host and detected services

        Returns:
            List of SSH attack recommendations
        """
        attacks = [
            {
                'technique_id': 'T1110.001',
                'name': 'SSH Password Guessing',
                'tool': 'caldera',
                'commands': [],
                'reason': 'Attempt to guess SSH credentials'
            },
            {
                'technique_id': 'T1110.002',
                'name': 'SSH Password Cracking',
                'tool': 'caldera',
                'commands': [],
                'reason': 'Attempt to crack SSH password hashes'
            },
            {
                'technique_id': 'T1021.004',
                'name': 'SSH Lateral Movement',
                'tool': 'caldera',
                'commands': [],
                'reason': 'Use SSH for lateral movement'
            }
        ]

        # If SSH version identified, check for known vulnerabilities
        ssh_version = target.get('service_details', {}).get('product_version', '')
        if ssh_version and 'OpenSSH' in ssh_version:
            if any(v in ssh_version.lower() for v in ['5.', '6.0', '6.1', '6.2', '6.3']):
                attacks.append({
                    'technique_id': 'T1190',
                    'name': 'OpenSSH Vulnerability Exploit',
                    'tool': 'caldera',
                    'commands': [],
                    'reason': f'Target running potentially vulnerable OpenSSH version: {ssh_version}'
                })

        return attacks

    def ftp_attacks(self, target: Dict) -> List[Dict]:
        """
        Generate FTP attack recommendations for the target

        Args:
            target: Target information including host and detected services

        Returns:
            List of FTP attack recommendations
        """
        attacks = [
            {
                'technique_id': 'T1110.001',
                'name': 'FTP Password Guessing',
                'tool': 'caldera',
                'commands': [],
                'reason': 'Attempt to guess FTP credentials'
            },
            {
                'technique_id': 'T1040',
                'name': 'FTP Traffic Sniffing',
                'tool': 'caldera',
                'commands': [],
                'reason': 'Capture unencrypted FTP credentials'
            },
            {
                'technique_id': 'T1213',
                'name': 'FTP Data Collection',
                'tool': 'caldera',
                'commands': [],
                'reason': 'Collect sensitive data from FTP server'
            }
        ]

        # If FTP version identified, check for known vulnerabilities
        ftp_version = target.get('service_details', {}).get('product_version', '')
        if ftp_version:
            if 'vsftpd' in ftp_version.lower() and '2.3.4' in ftp_version:
                attacks.append({
                    'technique_id': 'T1190',
                    'name': 'vsftpd Backdoor Exploit',
                    'tool': 'caldera',
                    'commands': [],
                    'reason': 'Target running vulnerable vsftpd 2.3.4 with backdoor'
                })

        # Check for anonymous FTP access
        if 'anonymous' in target.get('notes', '').lower():
            attacks.append({
                'technique_id': 'T1021.001',
                'name': 'Anonymous FTP Access',
                'tool': 'caldera',
                'commands': [],
                'reason': 'Target allows anonymous FTP access'
            })

        return attacks

    def smb_attacks(self, target: Dict) -> List[Dict]:
        """
        Generate SMB attack recommendations for the target

        Args:
            target: Target information including host and detected services

        Returns:
            List of SMB attack recommendations
        """
        attacks = [
            {
                'technique_id': 'T1110.001',
                'name': 'SMB Password Guessing',
                'tool': 'caldera',
                'commands': [],
                'reason': 'Attempt to guess SMB credentials'
            },
            {
                'technique_id': 'T1021.002',
                'name': 'SMB/Windows Admin Shares',
                'tool': 'caldera',
                'commands': [],
                'reason': 'Attempt to access administrative shares'
            },
            {
                'technique_id': 'T1135',
                'name': 'SMB Share Discovery',
                'tool': 'caldera',
                'commands': [],
                'reason': 'Discover available SMB shares'
            }
        ]

        # If SMB version identified, check for known vulnerabilities
        smb_version = target.get('service_details', {}).get('product_version', '')
        if smb_version:
            if 'samba' in smb_version.lower() and any(v in smb_version for v in ['3.', '4.1']):
                attacks.append({
                    'technique_id': 'T1190',
                    'name': 'EternalBlue SMB Exploit',
                    'tool': 'caldera',
                    'commands': [],
                    'reason': 'Target running vulnerable SMB version'
                })

        return attacks

    def http_attacks(self, target: Dict) -> List[Dict]:
        """
        Generate HTTP/HTTPS attack recommendations for the target

        Args:
            target: Target information including host and detected services

        Returns:
            List of HTTP attack recommendations
        """
        attacks = [
            {
                'technique_id': 'T1190',
                'name': 'Web Application Vulnerability Exploit',
                'tool': 'caldera',
                'commands': [],
                'reason': 'Attempt to exploit web application vulnerabilities'
            },
            {
                'technique_id': 'T1592.002',
                'name': 'Web Content Discovery',
                'tool': 'caldera',
                'commands': [],
                'reason': 'Discover web application directories and files'
            },
            {
                'technique_id': 'T1212',
                'name': 'Exploitation of Remote Services',
                'tool': 'caldera',
                'commands': [],
                'reason': 'Exploit vulnerable web services'
            }
        ]

        # If web server version identified, check for known vulnerabilities
        web_version = target.get('service_details', {}).get('product_version', '')
        if web_version:
            if 'apache' in web_version.lower() and '2.4.' in web_version:
                attacks.append({
                    'technique_id': 'T1190',
                    'name': 'Apache Vulnerability Exploit',
                    'tool': 'caldera',
                    'commands': [],
                    'reason': f'Target running Apache {web_version}'
                })
            elif 'nginx' in web_version.lower():
                attacks.append({
                    'technique_id': 'T1190',
                    'name': 'Nginx Vulnerability Exploit',
                    'tool': 'caldera',
                    'commands': [],
                    'reason': f'Target running Nginx {web_version}'
                })

        return attacks

    def rdp_attacks(self, target: Dict) -> List[Dict]:
        """
        Generate RDP attack recommendations for the target

        Args:
            target: Target information including host and detected services

        Returns:
            List of RDP attack recommendations
        """
        attacks = [
            {
                'technique_id': 'T1110.001',
                'name': 'RDP Password Guessing',
                'tool': 'caldera',
                'commands': [],
                'reason': 'Attempt to guess RDP credentials'
            },
            {
                'technique_id': 'T1021.001',
                'name': 'Remote Desktop Protocol',
                'tool': 'caldera',
                'commands': [],
                'reason': 'Use RDP for lateral movement'
            },
            {
                'technique_id': 'T1563.002',
                'name': 'RDP Hijacking',
                'tool': 'caldera',
                'commands': [],
                'reason': 'Hijack existing RDP sessions'
            }
        ]

        # Check for BlueKeep vulnerability (CVE-2019-0708)
        if target.get('os_type', '').lower() == 'windows' and any(
                v in target.get('os_version', '') for v in ['XP', '7', 'Server 2003', 'Server 2008']):
            attacks.append({
                'technique_id': 'T1210',
                'name': 'BlueKeep RDP Vulnerability',
                'tool': 'caldera',
                'commands': [],
                'reason': 'Target may be vulnerable to BlueKeep RDP exploit'
            })

        return attacks


class IntegratedAttackPlanner:
    """Integrates system and network attack modules to generate comprehensive attack plans"""

    def __init__(self, workspace: str = "./workspace"):
        """Initialize the attack planner with system and network attack modules"""
        self.workspace = Path(workspace)
        self.workspace.mkdir(exist_ok=True)
        self.logger = logging.getLogger(__name__)

        # Initialize attack modules
        self.system_module = SystemAttackModule(workspace)
        self.network_module = NetworkServiceAttackModule(workspace)

    def generate_attack_plan(self, scan_results: Dict) -> Dict:
        """
        Generate a comprehensive attack plan based on scan results

        Args:
            scan_results: Results from scanning phase

        Returns:
            Dictionary containing attack recommendations
        """
        attack_plan = {
            'phase': 'attack_planning',
            'system_attacks': [],
            'network_attacks': []
        }

        # Process each target from scan results
        for target in scan_results.get('scan_results', []):
            host = target.get('host', '')
            os_type = target.get('os_type', 'unknown')

            # Generate system attacks based on OS type
            if os_type.lower() in ['windows', 'linux']:
                attack_plan['system_attacks'].extend([
                    {
                        'host': host,
                        'os_type': os_type,
                        'authentication_attacks': self.system_module.authenticate_attacks(target, os_type),
                        'authorization_attacks': self.system_module.authorization_attacks(target, os_type),
                        'code_execution_attacks': self.system_module.code_execution_attacks(target, os_type)
                    }
                ])

            # Generate network service attacks based on detected services
            network_attacks = {
                'host': host,
                'services': {}
            }

            # Check for each service and add corresponding attacks
            services = target.get('services', {})
            for service_name, port in services.items():
                if 'ssh' in service_name.lower():
                    network_attacks['services']['ssh'] = self.network_module.ssh_attacks(target)
                elif 'ftp' in service_name.lower():
                    network_attacks['services']['ftp'] = self.network_module.ftp_attacks(target)
                elif 'smb' in service_name.lower() or 'microsoft-ds' in service_name.lower():
                    network_attacks['services']['smb'] = self.network_module.smb_attacks(target)
                elif 'http' in service_name.lower() or 'www' in service_name.lower():
                    network_attacks['services']['http'] = self.network_module.http_attacks(target)
                elif 'rdp' in service_name.lower() or 'ms-wbt-server' in service_name.lower():
                    network_attacks['services']['rdp'] = self.network_module.rdp_attacks(target)

            # Add network attacks if any services were found
            if network_attacks['services']:
                attack_plan['network_attacks'].append(network_attacks)

        # Get the top 3 recommended attacks based on priority
        attack_plan['top_recommendations'] = self._prioritize_attacks(attack_plan)

        return attack_plan

    def _prioritize_attacks(self, attack_plan: Dict) -> List[Dict]:
        """
        Prioritize attacks based on effectiveness and success probability

        Args:
            attack_plan: Complete attack plan

        Returns:
            List of top priority attack recommendations
        """
        all_attacks = []

        # Collect all system attacks
        for system_target in attack_plan.get('system_attacks', []):
            host = system_target.get('host', '')
            os_type = system_target.get('os_type', '')

            # Add authentication attacks
            for attack in system_target.get('authentication_attacks', []):
                all_attacks.append({
                    'host': host,
                    'category': 'system',
                    'attack_type': 'authentication',
                    'os_type': os_type,
                    'details': attack,
                    # Assign priority score: authentication attacks are medium priority
                    'priority': 5
                })

            # Add authorization attacks
            for attack in system_target.get('authorization_attacks', []):
                all_attacks.append({
                    'host': host,
                    'category': 'system',
                    'attack_type': 'authorization',
                    'os_type': os_type,
                    'details': attack,
                    # Assign priority score: authorization attacks are high priority
                    'priority': 8
                })

            # Add code execution attacks
            for attack in system_target.get('code_execution_attacks', []):
                all_attacks.append({
                    'host': host,
                    'category': 'system',
                    'attack_type': 'code_execution',
                    'os_type': os_type,
                    'details': attack,
                    # Assign priority score: code execution attacks are highest priority
                    'priority': 9
                })

        # Collect all network attacks
        for network_target in attack_plan.get('network_attacks', []):
            host = network_target.get('host', '')

            # Process each service
            for service_name, attacks in network_target.get('services', {}).items():
                for attack in attacks:
                    # Assign priority based on service type and attack
                    priority = 5  # Default medium priority

                    # Higher priority for known vulnerabilities
                    if 'vulnerability' in attack.get('name', '').lower() or 'exploit' in attack.get('name', '').lower():
                        priority = 9

                    # Higher priority for lateral movement attacks
                    elif 'lateral' in attack.get('name', '').lower():
                        priority = 7

                    # Higher priority for sensitive services
                    if service_name.lower() in ['smb', 'rdp']:
                        priority += 1

                    all_attacks.append({
                        'host': host,
                        'category': 'network',
                        'attack_type': service_name,
                        'details': attack,
                        'priority': priority
                    })

        # Sort attacks by priority (highest first) and return top 3
        return sorted(all_attacks, key=lambda x: x['priority'], reverse=True)[:3]


# Example usage
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    # Example scan results
    scan_results = {
        "scan_results": [
            {
                "host": "192.168.1.100",
                "os_type": "windows",
                "os_version": "Windows Server 2016",
                "services": {
                    "rdp": 3389,
                    "smb": 445,
                    "http": 80
                }
            },
            {
                "host": "192.168.1.101",
                "os_type": "linux",
                "os_version": "Ubuntu 18.04",
                "services": {
                    "ssh": 22,
                    "ftp": 21,
                    "http": 80
                }
            }
        ]
    }

    # Initialize attack planner
    planner = IntegratedAttackPlanner()

    # Generate attack plan
    attack_plan = planner.generate_attack_plan(scan_results)

    # Print summary
    print("\nSystem Attack Recommendations:")
    for target in attack_plan['system_attacks']:
        print(f"Target: {target['host']} ({target['os_type']})")
        print(f"  Authentication attacks: {len(target['authentication_attacks'])}")
        print(f"  Authorization attacks: {len(target['authorization_attacks'])}")
        print(f"  Code execution attacks: {len(target['code_execution_attacks'])}")

    print("\nNetwork Attack Recommendations:")
    for target in attack_plan['network_attacks']:
        print(f"Target: {target['host']}")
        for service, attacks in target['services'].items():
            print(f"  {service.upper()}: {len(attacks)} attack options")

    print("\nTop Recommended Attacks:")
    for i, attack in enumerate(attack_plan['top_recommendations']):
        print(f"{i + 1}. {attack['host']} - {attack['category'].upper()} - {attack['attack_type']}")
        print(f"   {attack['details']['name']}")
        print(f"   Reason: {attack['details']['reason']}")
        print(f"   Priority Score: {attack['priority']}/10")