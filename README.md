# KFUPM-ART
An automated End-end Red team platform, that covers Recon - Scanning - Exploitation - Reporting. the project utilize AI GPT for attack strategy and TTP recommendation, and will use caldera for the exploitation phase.

# ART: Automated Red Team Platform with AI-Driven MITRE ATT&CK-Guidance

An integrated penetration testing framework that automates and streamlines the vulnerability assessment process through MITRE ATT&CK framework integration and AI-guided attack planning.

![ART Platform](docs/images/art_platform_logo.png)

## Overview

This platform provides a unified workflow from reconnaissance through exploitation and reporting with intelligent decision-making capabilities using OpenAI GPT-4 model. The system combines open-source reconnaissance and scanning utilities with the Caldera exploitation framework, guided by large language models to improve attack vector selection.

Traditional penetration testing approaches require significant manual effort between phases and specialized expertise across multiple domains of offensive security. ART addresses these challenges by integrating the entire penetration testing lifecycle into a cohesive workflow while leveraging AI to enhance decision-making and prioritization.

## Key Features

- **End-to-end integration**: Seamless workflow from reconnaissance through exploitation to reporting
- **MITRE ATT&CK integration**: Structured mapping of vulnerabilities to attack techniques and tactics
- **AI-guided decision support**: Large language model assistance for technique selection and report generation
- **Modular architecture**: Extensible components for adding new scanning and exploitation capabilities
- **Comprehensive reporting**: Automated generation of executive summaries, technical reports, and visualizations
- **Intuitive GUI**: Real-time tracking and visualization of penetration testing progress

## System Architecture

The framework consists of six core modules designed to work in concert while maintaining separation of concerns:

1. **Information Gathering**: Performs target discovery and service enumeration using Nmap and other reconnaissance tools
2. **Vulnerability Scanning**: Identifies potential security weaknesses through basic scanning, enhanced CVE detection, and optional OpenVAS integration
3. **Attack Planning**: Maps vulnerabilities to MITRE ATT&CK techniques through direct CVE mappings, service-based heuristics, and AI-enhanced analysis
4. **Exploitation**: Executes controlled exploits via the Caldera framework with intelligent attack path selection
5. **AI Guidance**: Provides decision support using large language models for attack planning and report generation
6. **Reporting**: Transforms technical findings into professional security reports with executive summaries and actionable recommendations

## Prerequisites

- Python 3.10 or higher
- Nmap 7.80 or higher
- Kali Linux for best compatibility (Ubuntu and other Linux distributions also supported)
- OpenAI API key
- Caldera server (optional for exploitation)
- OpenVAS (optional for enhanced vulnerability scanning)

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/ART-Platform.git
cd ART-Platform

# Create a virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Set up configuration
cp config.example.yml config.yml
# Edit config.yml with your API keys and settings


## Setting up Caldera
Caldera is an optional component for the exploitation phase. To set up Caldera:

Clone the Caldera repository:
bashgit clone https://github.com/mitre/caldera.git
cd caldera

Install Caldera dependencies:
bashpip install -r requirements.txt

Start the Caldera server:
bashpython server.py --insecure

Access the Caldera web interface at http://localhost:8888 with default credentials:

Username: admin
Password: admin


Create a new API key in the Caldera web interface:

Navigate to the settings page
Click on "API Keys"
Create a new API key
Copy the key to your ART Platform's config.yml file



Setting up OpenAI API
To use the AI guidance features, you need an OpenAI API key:

Create an account at OpenAI
Navigate to API Keys
Create a new API key
Copy the key to your ART Platform's config.yml file in the appropriate section

Configuration
The platform uses a YAML configuration file for managing API keys and service connections:

Copy config.example.yml to config.yml
Add your OpenAI API key in the appropriate section
Configure Caldera API settings if you're using Caldera for exploitation
Set OpenVAS connection details if you're using enhanced scanning capabilities
Customize workspace and reporting directories as needed

Example configuration:
yaml# API Keys
api_keys:
  # Your OpenAI API key (required for AI guidance)
  openai: "sk-your-openai-api-key-here"

# Caldera Framework Integration
caldera:
  # URL to your Caldera server
  url: "http://localhost:8888"
  # API key for Caldera authentication
  api_key: "ADMIN123"
  # Default red team group
  group: "red"
  # Connection timeout in seconds
  timeout: 30

# OpenVAS Integration (optional)
openvas:
  # Set to true to enable OpenVAS integration
  enabled: false
  # OpenVAS/GVM connection settings
  host: "localhost"
  port: 9390
  username: "admin"
  password: "admin"

# Workspace Settings
workspace:
  # Base directory for all data and results
  base_directory: "./workspace"
  # Directory for generated reports
  reports_directory: "./reports"
  # Default report format (html, pdf, md)
  default_report_format: "html"
Usage
GUI Mode
bash# Run the GUI application
python main.py
The GUI provides an intuitive interface for configuring penetration tests, monitoring progress, and generating reports.
CLI Mode
bash# Run a full penetration test
python cli.py --target 192.168.1.0/24 --attack-type all

# System-focused penetration test
python cli.py --target 192.168.1.100 --target-type system --attack-type system

# Network service focused test
python cli.py --target 192.168.1.0/24 --attack-type network --output-dir ./custom_reports
Results and Performance
Our evaluation conducted across 15 target environments shows:

37% reduction in time-to-exploit compared to traditional manual approaches
42% increase in successful exploitation of high-risk vulnerabilities
93% vulnerability detection rate compared to 89% with standard tools
56% reduction in report generation time while maintaining professional standards

MetricART PlatformManual ApproachTime to exploit (avg.)26 minutes41 minutesVulnerability detection rate93%89%High-risk exploit success78%55%Avg. techniques attempted5.28.8Report generation time22 minutes50 minutes
Repository Structure
ART-Platform/
├── .github/
│   └── workflows/                # CI/CD workflows 
├── docs/                         # Documentation
│   ├── images/                   # Architecture diagrams and screenshots
│   ├── usage.md                  # Detailed usage instructions
│   └── api.md                    # API documentation
├── src/                          # Source code
│   ├── reconnaissance/           # Information gathering module
│   ├── scanning/                 # Vulnerability scanning module
│   ├── attack_modules/           # Attack planning and execution
│   ├── ai/                       # AI guidance integration
│   ├── mitre/                    # MITRE ATT&CK framework integration
│   ├── caldera/                  # Caldera framework integration
│   ├── reporting/                # Report generation module
│   ├── ui/                       # GUI implementation
│   ├── core/                     # Core orchestration
│   └── utils/                    # Utility functions
├── tests/                        # Test suite
├── data/                         # MITRE ATT&CK mapping data
├── templates/                    # Report templates
├── config.example.yml            # Example configuration file
├── requirements.txt              # Python dependencies
├── main.py                       # Main application entry point
├── cli.py                        # Command-line interface
├── LICENSE                       # MIT License
└── README.md                     # Project documentation
Research Paper
For a comprehensive explanation of our methodology, implementation, and results, please refer to our research paper:
ART: Automated Red Team Platform with AI-Driven MITRE ATT&CK-Guidance
Abstract: Red Team operations represent a critical practice for identifying security vulnerabilities in systems and networks, yet traditional approaches are resource-intensive and require highly skilled personnel. This paper presents an integrated penetration testing framework that automates and streamlines the vulnerability assessment process through MITRE ATT&CK framework integration and AI-guided attack planning. Unlike traditional tools that require significant manual intervention between phases, our solution provides a unified workflow from reconnaissance through exploitation and reporting with intelligent decision-making capabilities using OpenAI GPT-4 model. We developed a modular system combining open-source reconnaissance and scanning utilities with the Caldera exploitation framework, guided by large language models to improve attack vector selection and exploitation. Our evaluation conducted across 15 target environments shows a 37% reduction in time-to-exploit compared to traditional manual approaches, with a 42% increase in successful exploitation of high-risk vulnerabilities. Additionally, our reporting module reduces documentation time by 56% while maintaining professional standards. The framework demonstrates the potential for more efficient security assessments through intelligent automation while maintaining necessary human oversight, making comprehensive security testing more accessible to organizations with limited cybersecurity resources.
Read the full paper
Contributing
Contributions are welcome! Please feel free to submit a Pull Request.

Fork the repository
Create your feature branch (git checkout -b feature/amazing-feature)
Commit your changes (git commit -m 'Add some amazing feature')
Push to the branch (git push origin feature/amazing-feature)
Open a Pull Request

License
This project is licensed under the MIT License - see the LICENSE file for details.
Ethical Considerations
This tool is designed for legitimate security testing with proper authorization. Users are responsible for ensuring they have appropriate permissions before conducting any security tests. The system incorporates explicit authorization checks and maintains detailed audit logs to support accountability and responsible use.
Acknowledgments

MITRE ATT&CK® for providing the knowledge base that enables structured security testing
OpenAI for the GPT models that power the AI guidance component
The Caldera framework team for their extensible adversary emulation platform
The Python community for the excellent libraries and tools that make this project possible
