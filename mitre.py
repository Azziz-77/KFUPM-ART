from pyattck import Attck
from typing import List, Dict, Optional
import logging


class MITREMapper:
    def __init__(self):
        """Initialize the MITRE ATT&CK framework integration"""
        self.attack = Attck()
        self.logger = logging.getLogger(__name__)

    def get_technique_details(self, technique_id: str) -> Optional[Dict]:
        """Get detailed information about a specific technique"""
        for technique in self.attack.enterprise.techniques:
            if technique.id == technique_id:
                return {
                    'id': technique.id,
                    'name': technique.name,
                    'description': technique.description,
                    'platforms': technique.platforms,
                    'permissions_required': technique.permissions_required,
                    'detection': technique.detection,
                    'mitigation': technique.mitigation
                }
        return None

    def map_vulnerabilities_to_techniques(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """Map discovered vulnerabilities to MITRE ATT&CK techniques"""
        mapped_techniques = []

        # Common vulnerability to technique mappings
        vuln_technique_map = {
            'sql_injection': 'T1190',  # Exploit Public-Facing Application
            'rce': 'T1203',  # Exploitation for Client Execution
            'file_inclusion': 'T1505',  # Server Software Component
            'path_traversal': 'T1083',  # File and Directory Discovery
            'xss': 'T1059',  # Command and Scripting Interpreter
        }

        for vuln in vulnerabilities:
            vuln_type = vuln.get('type', '').lower()
            if vuln_type in vuln_technique_map:
                technique_id = vuln_technique_map[vuln_type]
                technique_details = self.get_technique_details(technique_id)
                if technique_details:
                    mapped_techniques.append({
                        'technique': technique_details,
                        'vulnerability': vuln,
                        'confidence': 'high'
                    })

        return mapped_techniques

    def validate_technique(self, technique_id: str) -> bool:
        """Validate if a technique exists in MITRE ATT&CK"""
        return bool(self.get_technique_details(technique_id))

    def get_recommended_techniques(self, service_info: Dict) -> List[Dict]:
        """Get recommended techniques based on service information"""
        recommendations = []

        # Map service types to likely techniques
        service_technique_map = {
            'http': ['T1190', 'T1505'],  # Web-related techniques
            'ssh': ['T1110'],  # Brute Force
            'ftp': ['T1213'],  # Data from Information Repositories
            'smb': ['T1021.002'],  # Remote Services: SMB
            'database': ['T1190', 'T1213']  # SQL-related techniques
        }

        service_type = service_info.get('service', '').lower()
        if service_type in service_technique_map:
            for technique_id in service_technique_map[service_type]:
                technique_details = self.get_technique_details(technique_id)
                if technique_details:
                    recommendations.append({
                        'technique': technique_details,
                        'service': service_info,
                        'confidence': 'medium'
                    })

        return recommendations