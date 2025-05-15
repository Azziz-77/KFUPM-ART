# KFUPM-ART: AI-Guided Penetration Testing Tool
An automated penetration testing framework that uses AI guidance from GPT-4 to streamline security assessments.


<img src="https://github.com/user-attachments/assets/1b79457d-4df0-49cc-a54d-1b9cf08230d2" alt="Alt Text" width="600" height="600">



## Overview

This platform provides a unified workflow from reconnaissance through exploitation and reporting with intelligent decision-making capabilities using OpenAI GPT-4 model. The system combines open-source reconnaissance and scanning utilities with the Metasploit and Caldera frameworks, guided by large language models to improve attack vector selection.

Traditional penetration testing approaches require significant manual effort between phases and specialized expertise across multiple domains of offensive security. ART addresses these challenges by integrating the entire penetration testing lifecycle into a cohesive workflow while leveraging AI to enhance decision-making and prioritization.


## Key Features

- **AI-guided decision support**: Large language model assistance for technique selection and report generation
- **Modular architecture**: Extensible components for adding new scanning and exploitation capabilities
- **Comprehensive reporting**: Automated generation of executive summaries, technical reports, and visualizations
- **Intuitive GUI**: Real-time tracking of penetration testing progress

## System Architecture

The framework consists of several core modules designed to work in concert:
<img src="https://github.com/user-attachments/assets/a27a4ff9-2bd2-49aa-8c8f-f9ce4cac057b" alt="Alt Text" width="600" height="600">


1. **AI Controller**: The central module that orchestrates the entire workflow. It interfaces with the OpenAI API to generate prompts and process responses, maintains conversation history, and coordinates between different tool interfaces.

2. **Scanner Interface**: Handles host discovery and service enumeration through tools like Nmap. It processes scan results and formats them for use by other components of the system.

3. **Metasploit Interface**: Provides an abstraction layer for interacting with the Metasploit Framework. It handles session management, exploit execution, and exploitation activities through both direct command execution and RPC-based interaction.

4. **CALDERA Interface**: A planned feature for future implementation to support post-exploitation activities. Currently in development.

5. **GUI**: A PyQt6-based graphical user interface that provides an accessible way to configure, monitor, and control the penetration testing process.

## Prerequisites

- Python 3.10 or higher
- Kali Linux for best compatibility
- OpenAI API key
- Caldera server (optional for post exploitation)

## Installation

```bash
# Clone the repository
git clone https://github.com/Azziz-77/KFUPM-ART.git
cd KFUPM-ART

# Run the setup script (requires root privileges)
sudo ./setup.sh

# Install dependencies
pip install -r requirements.txt

```

## Metasploit RPC Configuration
The framework interacts with Metasploit through its RPC interface. To set it up:

```bash
# Start the Metasploit RPC server
msfrpcd -P password -S -a 127.0.0.1 -p 55553
```

## Setting up Caldera

Caldera is an optional component for the exploitation phase. To set up Caldera:



```bash 
# Clone the Caldera repository:
git clone https://github.com/mitre/caldera.git
cd caldera

# Install Caldera dependencies:
pip install -r requirements.txt

# Navigate to Caldera 
cd caldera 

# Create a virtual environment with an old version of python that supports Caldera
python3.12 -m venv py312-venv

# Activate it
source py312-venv/bin/activate

# Start the Caldera server:
python3 server.py --insecure --build




# Access the Caldera web interface at http://localhost:8888 with default credentials:

Username: admin
Password: admin




```


## Setting up OpenAI API
To use the AI guidance features, you need an OpenAI API key:

* Create an account at OpenAI
* Navigate to API Keys
* Create a new API key
* Copy the key to your ART Platform's GUI in the appropriate section


## Workspace Settings
workspace:
  #### Base directory for all data and results
  base_directory: "./workspace"

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
- The Metasploit Framework team for their comprehensive exploitation toolkit
