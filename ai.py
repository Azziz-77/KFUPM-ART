from openai import OpenAI
import logging
from typing import Dict, List, Optional
import json
from .mitre import MITREMapper


class OpenAIGuide:
    def __init__(self, api_key: str):
        """Initialize OpenAI guide with API key"""
        self.client = OpenAI(api_key=api_key)
        self.mitre_mapper = MITREMapper()
        self.logger = logging.getLogger(__name__)

    def analyze_vulnerabilities(self, scan_results: Dict) -> List[Dict]:
        """Analyze scan results and suggest attack techniques"""
        prompt = self._create_analysis_prompt(scan_results)

        try:
            response = self.client.chat.completions.create(
                model="gpt-4",
                messages=[
                    {
                        "role": "system",
                        "content": """You are a professional penetration tester with expertise in vulnerability analysis 
                        and exploitation. Analyze scan results and suggest possible attack vectors, mapping them to 
                        MITRE ATT&CK techniques."""
                    },
                    {"role": "user", "content": prompt}
                ],
                temperature=0.7
            )

            recommendations = json.loads(response.choices[0].message.content)
            return self._validate_recommendations(recommendations)

        except Exception as e:
            self.logger.error(f"Error getting AI recommendations: {str(e)}")
            return []

    def _create_analysis_prompt(self, scan_results: Dict) -> str:
        """Create detailed prompt for vulnerability analysis"""
        return f"""
        Analyze these scan results and suggest possible attack techniques:
        {json.dumps(scan_results, indent=2)}

        For each vulnerability or finding, suggest:
        1. The most appropriate MITRE ATT&CK technique
        2. Specific tools or exploits that could work
        3. Required conditions for successful exploitation
        4. Potential risks and likelihood of success

        Format your response as a JSON array of objects with the following structure:
        [
            {{
                "technique_id": "MITRE technique ID (e.g., T1190)",
                "name": "Name of the attack technique",
                "commands": ["specific exploit commands to try"],
                "reason": "Detailed explanation of why this attack would work",
                "prerequisites": ["required conditions"],
                "risk_level": "high/medium/low",
                "likelihood": "high/medium/low"
            }}
        ]

        Focus on practical, actionable techniques based on the discovered vulnerabilities.
        """

    def _validate_recommendations(self, recommendations: List[Dict]) -> List[Dict]:
        """Validate AI recommendations against MITRE ATT&CK framework"""
        validated_recommendations = []

        for rec in recommendations:
            if self.mitre_mapper.validate_technique(rec.get('technique_id', '')):
                technique_details = self.mitre_mapper.get_technique_details(rec['technique_id'])
                if technique_details:
                    rec['technique_details'] = technique_details
                    validated_recommendations.append(rec)
            else:
                self.logger.warning(f"Invalid technique ID: {rec.get('technique_id')}")

        return validated_recommendations

    def suggest_exploits(self, vulnerability: Dict) -> List[Dict]:
        """Suggest specific exploits for a given vulnerability"""
        prompt = f"""
        For this vulnerability:
        {json.dumps(vulnerability, indent=2)}

        Suggest specific exploits and attack methods, including:
        1. Metasploit modules if applicable
        2. Manual exploitation techniques
        3. Required tools and configurations
        """

        try:
            response = self.client.chat.completions.create(
                model="gpt-4",
                messages=[
                    {"role": "system", "content": "You are an exploit development expert."},
                    {"role": "user", "content": prompt}
                ]
            )

            return json.loads(response.choices[0].message.content)

        except Exception as e:
            self.logger.error(f"Error suggesting exploits: {str(e)}")
            return []