# KFUPM-ART
An automated End-end Red team platform, that covers Recon - Scanning - Exploitation - Reporting. the project utilize AI GPT for attack strategy and TTP recommendation, and will use caldera for the exploitation phase.



# ART: Automated Red Team Platform with AI-Driven MITRE ATT&CK-Guidance

An integrated penetration testing framework that automates and streamlines the vulnerability assessment process through MITRE ATT&CK framework integration and AI-guided attack planning.

![KFUPM ART](https://github.com/user-attachments/assets/84be8050-569a-4ebf-8068-cc676c4f53bb)


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


```

## Setting up Caldera

Caldera is an optional component for the exploitation phase. To set up Caldera:



```bash 
# Clone the Caldera repository:
bashgit clone https://github.com/mitre/caldera.git
cd caldera

# Install Caldera dependencies:
bashpip install -r requirements.txt

# Start the Caldera server:
bashpython server.py --insecure

# Access the Caldera web interface at http://localhost:8888 with default credentials:

Username: admin
Password: admin


# Create a new API key in the Caldera web interface:

Navigate to the settings page
Click on "API Keys"
Create a new API key
Copy the key to your ART Platform's config.yml file


```


## Setting up OpenAI API
To use the AI guidance features, you need an OpenAI API key:

* Create an account at OpenAI
* Navigate to API Keys
* Create a new API key
* Copy the key to your ART Platform's GUI in the appropriate section

## GUI overview
![image](https://github.com/user-attachments/assets/9e68b24c-b5d7-4772-a3f0-d1dcdffe84df)


## GUI configuration
Add your OpenAI API key in the appropriate section in the left
Configure Caldera API settings
Set OpenVAS connection details if you're using enhanced scanning capabilities
Customize workspace and reporting directories as needed

Example configuration:
api_keys:
## Your OpenAI API key (required for AI guidance)
  openai: "sk-your-openai-api-key-here"

## Caldera Framework Integration
caldera:
  #### URL to your Caldera server
  url: "http://localhost:8888"
  #### API key for Caldera authentication
  api_key: "ADMIN123"
  #### Default red team group
  group: "red"
  #### Connection timeout in seconds
  timeout: 30

## OpenVAS Integration (optional)
openvas:
  #### Set to true to enable OpenVAS integration
  enabled: false
  #### OpenVAS/GVM connection settings
  host: "localhost"
  port: 9390
  username: "admin"
  password: "admin"

## Workspace Settings
workspace:
  #### Base directory for all data and results
  base_directory: "./workspace"
  #### Directory for generated reports
  reports_directory: "./reports"
  #### Default report format (html, pdf, md)
  default_report_format: "html"

## Usage
The GUI provides an intuitive interface for configuring penetration tests, monitoring progress, and generating reports.
You are required to install Pycharm and run it as root (sudo) in order to have a smooth experience


# Disclaimer
This tool is designed for legitimate security testing with proper authorization. Users are responsible for ensuring they have appropriate permissions before conducting any security tests. The system incorporates explicit authorization checks and maintains detailed audit logs to support accountability and responsible use.

# Acknowledgments
- MITRE ATT&CK® for providing the knowledge base that enables structured security testing
- OpenAI for the GPT models that power the AI guidance component
- The Caldera framework team for their extensible adversary emulation platform
- The Python community for the excellent libraries and tools that make this project possible
