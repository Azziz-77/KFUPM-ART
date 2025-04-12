import sys
import os
import json
import time
from pathlib import Path
from typing import Dict, List, Optional

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QLineEdit, QTextEdit, QTabWidget,
    QGroupBox, QFormLayout, QFileDialog, QMessageBox, QComboBox,
    QProgressBar, QTableWidget, QTableWidgetItem, QHeaderView,
    QSplitter, QToolBar, QStatusBar, QCheckBox, QRadioButton, QButtonGroup
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer, QSize
from PyQt6.QtGui import QIcon, QFont, QAction, QPixmap, QColor

# Import project modules - uncomment these lines
from reconnaissance import InformationGathering
from scanning import Scanning
from enhanced_scanning import EnhancedScanning


from openvas_scanner import OpenVASScanner
from caldera_exploitation import CalderaExploitation
from attack_modules import IntegratedAttackPlanner, SystemAttackModule, NetworkServiceAttackModule
from test_openaiAPI import OpenAIGuide

# Define some styling constants
HEADER_STYLE = "QLabel { font-size: 16px; font-weight: bold; }"
SECTION_STYLE = "QGroupBox { font-weight: bold; border: 1px solid #cccccc; border-radius: 5px; margin-top: 10px; }"
SUCCESS_STYLE = "color: green;"
ERROR_STYLE = "color: red;"
WARNING_STYLE = "color: orange;"


class PentestWorker(QThread):
    """Worker thread to run pentest operations in the background"""
    update_signal = pyqtSignal(str, str)  # (message, type)
    progress_signal = pyqtSignal(int)
    result_signal = pyqtSignal(dict)
    finished_signal = pyqtSignal()

    def __init__(self, operation, target_type, target, api_key, caldera_url, caldera_key, workspace,
                 attack_type=None, use_openvas=False, openvas_config=None):
        super().__init__()
        self.operation = operation
        self.target_type = target_type  # 'system' or 'network'
        self.target = target
        self.api_key = api_key
        self.caldera_url = caldera_url
        self.caldera_key = caldera_key
        self.workspace = workspace
        self.attack_type = attack_type  # 'system', 'network', or None for both
        self.use_openvas = use_openvas
        self.openvas_config = openvas_config
        self.results = {}



    def run(self):
        try:
            # Initialize and run modules based on the operation
            if self.operation == "reconnaissance":
                self.update_signal.emit(f"Starting reconnaissance on {self.target} ({self.target_type})", "info")
                self.progress_signal.emit(10)

                try:
                    recon = InformationGathering()
                    self.update_signal.emit("Initialized reconnaissance module", "info")

                    # Update progress to show we're starting the scan
                    self.progress_signal.emit(30)

                    try:
                        # Use a different approach for system vs network
                        if self.target_type == "system":
                            # For a system, add /32 if needed
                            if "/" not in self.target:
                                target_cidr = f"{self.target}/32"
                            else:
                                target_cidr = self.target
                        else:
                            target_cidr = self.target

                        self.update_signal.emit(f"Running host discovery on {target_cidr}", "info")

                        # Call reconnaissance with proper error handling
                        results = self._run_with_timeout(
                            recon.gather_information,
                            args=(target_cidr,),
                            timeout_seconds=600  # Adjust timeout as needed
                        )

                        if isinstance(results, dict) and results.get("timeout", False):
                            self.update_signal.emit("Reconnaissance timed out. Using partial results.", "warning")
                            # Create basic results in case of timeout
                            results = {
                                "network_summary": {
                                    "target_network": self.target,
                                    "live_hosts": [self.target.split('/')[0]] if '/' in self.target else [self.target]
                                },
                                "host_details": {}
                            }

                        # Make sure we have the expected result structure
                        if not isinstance(results, dict):
                            self.update_signal.emit("Warning: Unexpected result type from reconnaissance", "warning")
                            results = {
                                "network_summary": {
                                    "target_network": target_cidr,
                                    "live_hosts": []
                                },
                                "host_details": {}
                            }

                        # Make sure we have required keys
                        if "network_summary" not in results:
                            results["network_summary"] = {"target_network": target_cidr, "live_hosts": []}
                        if "host_details" not in results:
                            results["host_details"] = {}

                        # Update progress
                        self.progress_signal.emit(90)

                        # Log the scan completion
                        live_hosts = len(results.get("network_summary", {}).get("live_hosts", []))
                        self.update_signal.emit(f"Reconnaissance completed. Found {live_hosts} live hosts.", "success")

                        # Send results to GUI
                        self.progress_signal.emit(100)
                        self.result_signal.emit(results)

                    except Exception as e:
                        self.update_signal.emit(f"Error during host discovery: {str(e)}", "error")

                        # Create minimal results to prevent GUI errors
                        results = {
                            "network_summary": {
                                "target_network": self.target,
                                "live_hosts": [self.target.split('/')[0]] if '/' in self.target else [self.target]
                            },
                            "host_details": {}
                        }

                        # Still update the UI with what we have
                        self.progress_signal.emit(100)
                        self.result_signal.emit(results)

                except Exception as e:
                    self.update_signal.emit(f"Critical error during reconnaissance: {str(e)}", "error")

                    # Create minimal results even in case of major failure
                    results = {
                        "error": str(e),
                        "network_summary": {"target_network": self.target, "live_hosts": []},
                        "host_details": {}
                    }

                    self.progress_signal.emit(100)
                    self.result_signal.emit(results)

            elif self.operation == "scanning":
                self.update_signal.emit(f"Starting vulnerability scanning on {self.target} ({self.target_type})",
                                        "info")
                self.progress_signal.emit(10)

                try:
                    # Choose scanner based on configuration
                    if self.use_openvas:
                        # Initialize OpenVAS scanning module
                        from openvas_scanner import OpenVASScanner
                        scanner = OpenVASScanner(self.workspace)

                        # Configure OpenVAS connection if settings provided
                        if self.openvas_config:
                            scanner.configure_openvas(
                                self.openvas_config.get("host", "localhost"),
                                self.openvas_config.get("port", 9390),
                                self.openvas_config.get("username", "admin"),
                                self.openvas_config.get("password", "admin")
                            )

                        scanner_name = "OpenVAS"
                        self.update_signal.emit("Using OpenVAS for vulnerability scanning", "info")
                    else:
                        # Initialize regular scanning module
                        from scanning import Scanning
                        # scanner = Scanning(self.workspace)
                        scanner = EnhancedScanning(self.workspace)

                        scanner_name = "Basic Scanner"
                        self.update_signal.emit("Using basic scanner for vulnerability scanning", "info")

                    # Connect callbacks for progress and status updates
                    scanner.add_progress_callback(self.progress_signal.emit)
                    scanner.add_status_callback(self.update_signal.emit)

                    # Determine scan type based on attack focus
                    if self.attack_type == "system":
                        scan_type = "system"
                        self.update_signal.emit(
                            f"Performing system vulnerability scan using {scanner_name}", "info")
                    elif self.attack_type == "network":
                        scan_type = "network"
                        self.update_signal.emit(
                            f"Performing network services scan using {scanner_name}", "info")
                    else:
                        # Default to both if no specific focus
                        scan_type = "both"
                        self.update_signal.emit(
                            f"Performing comprehensive vulnerability scan using {scanner_name}", "info")

                    # Perform the scan with appropriate focus
                    scan_results = scanner.perform_comprehensive_scan(
                        self.target,
                        scan_type=scan_type
                    )

                    # Send results to GUI
                    self.progress_signal.emit(100)

                    # Create friendly summary for status message
                    vuln_count = scan_results["summary"].get("vulnerabilities_found", 0)
                    scanner_used = scan_results["summary"].get("scanner", scanner_name)

                    self.update_signal.emit(
                        f"Vulnerability scanning completed using {scanner_used} - found {vuln_count} vulnerabilities",
                        "success"
                    )
                    self.result_signal.emit(scan_results)

                except Exception as e:
                    self.update_signal.emit(f"Error during vulnerability scanning: {str(e)}", "error")
                    self.progress_signal.emit(100)  # Ensure progress completes

                    # Create minimal results on error
                    scan_results = {
                        "scan_results": [{
                            "host": self.target,
                            "os_type": "unknown",
                            "vulnerabilities": {}
                        }],
                        "summary": {
                            "target": self.target,
                            "scan_type": self.attack_type if self.attack_type else "both",
                            "vulnerabilities_found": 0,
                            "error": str(e)
                        }
                    }

                    # Still return results to avoid GUI errors
                    self.result_signal.emit(scan_results)


            elif self.operation == "exploitation":
                self.update_signal.emit(f"Starting exploitation phase on {self.target} ({self.target_type})", "info")
                self.progress_signal.emit(10)

                try:
                    # Initialize attack modules based on selected attack type
                    if self.attack_type == "system" or self.attack_type is None:
                        # Initialize system attack modules
                        system_module = SystemAttackModule(self.workspace)
                        self.update_signal.emit("Initialized system attack module", "info")

                    if self.attack_type == "network" or self.attack_type is None:
                        # Initialize network attack modules
                        network_module = NetworkServiceAttackModule(self.workspace)
                        self.update_signal.emit("Initialized network service attack module", "info")

                    # Initialize Caldera for exploitation with OpenAI integration
                    self.update_signal.emit("Connecting to Caldera server...", "info")

                    caldera = CalderaExploitation(
                        api_url=self.caldera_url,
                        api_key=self.caldera_key,
                        openai_api_key=self.api_key,  # Pass OpenAI API key for AI-guided exploitation
                        workspace=self.workspace
                    )

                    if not caldera.test_connection():
                        self.update_signal.emit("Failed to connect to Caldera server", "error")
                        raise Exception("Caldera connection failed")

                    self.update_signal.emit("Successfully connected to Caldera server", "success")
                    self.progress_signal.emit(30)

                    # Prepare target scan results
                    if self.target_type == "system":
                        scan_results = {
                            "scan_results": [{
                                "host": self.target,
                                "os_type": self._guess_os_type(),
                                "services": self._get_available_services_dict(),
                                "port": 0,
                                "service": ""
                            }]
                        }
                    else:
                        # For a network target
                        scan_results = {
                            "scan_results": [{
                                "host": self.target.split('/')[0],  # Remove CIDR notation if present
                                "os_type": "unknown",
                                "services": self._get_available_services_dict(),
                                "port": 0,
                                "service": ""
                            }]
                        }

                    # Generate attack recommendations based on attack type
                    recommendations = []

                    if self.attack_type == "system" or self.attack_type is None:
                        # Create an attack planner
                        planner = IntegratedAttackPlanner(self.workspace)
                        attack_plan = planner.generate_attack_plan(scan_results)

                        # Use top recommendations
                        recommendations.extend(
                            self._convert_to_caldera_format(attack_plan.get('top_recommendations', [])))

                    if self.attack_type == "network" or self.attack_type is None:
                        # Add some network-specific attack recommendations
                        services = self._get_available_services()
                        if 'ssh' in services:
                            recommendations.append({
                                'technique_id': 'T1110.001',
                                'name': 'SSH Password Guessing',
                                'tool': 'caldera',
                                'commands': [],
                                'reason': 'Target has SSH service'
                            })

                        if 'http' in services:
                            recommendations.append({
                                'technique_id': 'T1190',
                                'name': 'Exploit Public-Facing Application',
                                'tool': 'caldera',
                                'commands': [],
                                'reason': 'Target has HTTP service'
                            })

                    if not recommendations:
                        # Fallback to a generic recommendation
                        recommendations.append({
                            'technique_id': 'T1133',
                            'name': 'External Remote Services',
                            'tool': 'caldera',
                            'commands': [],
                            'reason': 'Generic attack vector'
                        })

                    # Log recommendations for debugging
                    self.update_signal.emit(f"Using {len(recommendations)} attack techniques", "info")
                    for rec in recommendations:
                        self.update_signal.emit(f"  - {rec['name']} ({rec['technique_id']}): {rec['reason']}", "info")

                    self.progress_signal.emit(50)
                    self.update_signal.emit(f"Executing exploitation with {len(recommendations)} techniques", "info")

                    # This is the critical part - we need to add more status updates during the operation
                    self.update_signal.emit("Starting exploitation phase - this may take a few minutes...", "info")

                    # Execute the exploitation phase
                    results = caldera.execute_exploitation_phase(scan_results, recommendations)

                    # Log for debugging
                    self.update_signal.emit(f"Exploitation completed with status: {results.get('phase', 'unknown')}",
                                            "info")

                    # Make sure we handle errors properly
                    if results.get('errors'):
                        for error in results.get('errors', []):
                            self.update_signal.emit(f"Exploitation error: {error.get('error', 'Unknown error')}",
                                                    "error")

                    self.progress_signal.emit(100)

                    successful = len(results.get('successful_exploits', []))
                    if successful > 0:
                        self.update_signal.emit(f"Exploitation complete with {successful} successful exploits",
                                                "success")
                    else:
                        self.update_signal.emit("Exploitation complete but no successful exploits", "warning")

                    self.result_signal.emit(results)

                except Exception as e:
                    import traceback
                    tb = traceback.format_exc()
                    self.update_signal.emit(f"Error during exploitation: {str(e)}", "error")
                    self.update_signal.emit(f"Error details: {tb}", "error")

                    # Still emit a result so the GUI doesn't hang
                    error_results = {
                        'phase': 'exploitation',
                        'errors': [{'error': str(e)}],
                        'successful_exploits': [],
                        'failed_targets': [{
                            'target': {'host': self.target},
                            'error': str(e)
                        }]
                    }
                    self.result_signal.emit(error_results)

            elif self.operation == "full_pentest":
                self.update_signal.emit(f"Starting full penetration test on {self.target} ({self.target_type})", "info")
                self.progress_signal.emit(5)

                try:
                    # Use the Orchestrator to run the full pentest
                    from orchestrator import PenetrationTestOrchestrator

                    self.update_signal.emit("Initializing penetration test orchestrator", "info")

                    # Initialize with appropriate settings
                    orchestrator = PenetrationTestOrchestrator(
                        target_network=self.target,
                        openai_api_key=self.api_key,
                        caldera_api_url=self.caldera_url,
                        caldera_api_key=self.caldera_key,
                        workspace=self.workspace
                    )

                    self.update_signal.emit("Starting full penetration test workflow", "info")
                    self.progress_signal.emit(10)

                    # Run the full test with the specified target and attack types
                    # Note: You'll need to modify your orchestrator to accept these parameters
                    # This is a placeholder for how it might work
                    results = orchestrator.run_full_pentest(target_type=self.target_type, attack_type=self.attack_type)

                    self.progress_signal.emit(100)
                    self.update_signal.emit("Full penetration test completed successfully", "success")
                    self.result_signal.emit(results)

                except Exception as e:
                    self.update_signal.emit(f"Error during full penetration test: {str(e)}", "error")
                    raise

        except Exception as e:
            import traceback
            tb = traceback.format_exc()
            self.update_signal.emit(f"Error in {self.operation}: {str(e)}", "error")
            self.update_signal.emit(f"Error details: {tb}", "error")
            self.progress_signal.emit(100)  # Set to 100 to indicate completion

            # Create minimal results with error info
            self.result_signal.emit({
                "error": str(e),
                "operation": self.operation,
                "status": "failed"
            })

        finally:
            self.finished_signal.emit()

    # Inside the PentestWorker class, add this method:

    def _run_with_timeout(self, func, args=(), kwargs={}, timeout_seconds=60):
        """Run a function with timeout"""
        import threading
        import time

        result = {"completed": False, "result": None, "error": None}

        def target_func():
            try:
                result["result"] = func(*args, **kwargs)
                result["completed"] = True
            except Exception as e:
                result["error"] = str(e)

        thread = threading.Thread(target=target_func)
        thread.daemon = True
        thread.start()

        # Wait for thread to complete or timeout
        start_time = time.time()
        while thread.is_alive() and time.time() - start_time < timeout_seconds:
            time.sleep(0.5)
            # Update progress while waiting
            elapsed = time.time() - start_time
            progress = 30 + min(int(60 * elapsed / timeout_seconds), 60)
            self.progress_signal.emit(progress)

        if not result["completed"]:
            return {"timeout": True}
        elif result["error"]:
            raise Exception(result["error"])
        else:
            return result["result"]

    def _detect_os_type(self, scan_data):
        """Try to detect OS type from scan data"""
        for port, details in scan_data.items():
            if isinstance(details, dict):
                service = details.get("name", "").lower()
                if "windows" in service or "microsoft" in service:
                    return "windows"
                elif "ssh" in service or "linux" in service:
                    return "linux"
        return "unknown"

    def _extract_services(self, scan_data):
        """Extract services from scan data"""
        services = {}
        for port, details in scan_data.items():
            if isinstance(details, dict):
                service_name = details.get("name", "unknown")
                services[service_name] = int(port)
        return services

    def _guess_os_type(self):
        """Make a simple guess about the OS type based on target"""
        # This is a placeholder - in real implementation, you would use previous scan data
        return "linux" if self.target_type == "system" else "unknown"

    def _get_available_services(self):
        """Return a list of available services"""
        # For demonstration, return some common services
        # In a real implementation, this would be based on previous scan results
        return ["ssh", "http", "ftp", "smb"]

    def _get_available_services_dict(self):
        """Return a dict of available services with port numbers"""
        # For demonstration, return some common services with their default ports
        return {
            "ssh": 22,
            "http": 80,
            "https": 443,
            "ftp": 21,
            "smb": 445
        }

    def _convert_to_caldera_format(self, recommendations):
        """Convert attack recommendations to Caldera format"""
        caldera_recommendations = []

        for rec in recommendations:
            details = rec.get('details', {})
            caldera_recommendations.append({
                'technique_id': details.get('technique_id', ''),
                'name': details.get('name', ''),
                'tool': 'caldera',
                'commands': [],
                'reason': details.get('reason', '')
            })

        return caldera_recommendations


class PenetrationTestingGUI(QMainWindow):
    """Main GUI window for the penetration testing tool"""

    def __init__(self):
        super().__init__()

        self.setWindowTitle("Advanced Penetration Testing Suite")
        self.setGeometry(100, 100, 1200, 800)

        # Initialize variables
        self.workspace = str(Path.home() / "pentest_workspace")
        self.results = {}
        self.worker = None

        # Initialize worker and related variables
        self.worker = None
        self.current_worker = None
        self.completed_workers = []  # Keep track of completed workers

        # Add a watchdog timer to ensure application keeps running
        self.keepalive_timer = QTimer(self)
        self.keepalive_timer.timeout.connect(self.check_status)
        self.keepalive_timer.start(1000)  # Check every second

        # Create main layout
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)

        self.main_layout = QVBoxLayout(self.central_widget)

        # Create and add toolbar
        self.create_toolbar()

        # Create main content layout with input panel and results
        content_splitter = QSplitter(Qt.Orientation.Horizontal)
        self.main_layout.addWidget(content_splitter)

        # Left panel - Input form
        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)
        left_layout.setContentsMargins(10, 10, 10, 10)

        # Configuration section
        config_group = QGroupBox("Configuration")
        config_group.setStyleSheet(SECTION_STYLE)
        config_layout = QFormLayout()

        # Target Type selection (System or Network)
        target_type_layout = QHBoxLayout()
        self.target_type_group = QButtonGroup()

        self.target_system_radio = QRadioButton("System")
        self.target_system_radio.setChecked(True)  # Default to System
        self.target_system_radio.toggled.connect(self.toggle_target_type)
        self.target_type_group.addButton(self.target_system_radio)
        target_type_layout.addWidget(self.target_system_radio)

        self.target_network_radio = QRadioButton("Network")
        self.target_network_radio.toggled.connect(self.toggle_target_type)
        self.target_type_group.addButton(self.target_network_radio)
        target_type_layout.addWidget(self.target_network_radio)

        config_layout.addRow("Target Type:", target_type_layout)

        # Target input
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("e.g., 192.168.1.100")
        config_layout.addRow("Target:", self.target_input)

        # OpenAI API Key
        self.api_key_input = QLineEdit()
        self.api_key_input.setPlaceholderText("sk-...")
        self.api_key_input.setEchoMode(QLineEdit.EchoMode.Password)
        config_layout.addRow("OpenAI API Key:", self.api_key_input)

        # Caldera URL
        self.caldera_url_input = QLineEdit("http://localhost:8888")
        config_layout.addRow("Caldera URL:", self.caldera_url_input)

        # Caldera API Key
        self.caldera_key_input = QLineEdit("ADMIN123")
        config_layout.addRow("Caldera API Key:", self.caldera_key_input)

        # Workspace directory
        workspace_layout = QHBoxLayout()
        self.workspace_input = QLineEdit(self.workspace)
        workspace_layout.addWidget(self.workspace_input)

        workspace_button = QPushButton("Browse...")
        workspace_button.clicked.connect(self.browse_workspace)
        workspace_layout.addWidget(workspace_button)

        config_layout.addRow("Workspace:", workspace_layout)

        config_group.setLayout(config_layout)
        left_layout.addWidget(config_group)

        # Attack Types section (System or Network)
        attack_group = QGroupBox("Attack Focus")
        attack_group.setStyleSheet(SECTION_STYLE)
        attack_layout = QVBoxLayout()

        # Attack Type selection
        attack_type_layout = QHBoxLayout()
        self.attack_type_group = QButtonGroup()

        self.attack_all_radio = QRadioButton("All Attacks")
        self.attack_all_radio.setChecked(True)  # Default to All
        self.attack_type_group.addButton(self.attack_all_radio)
        attack_type_layout.addWidget(self.attack_all_radio)

        self.attack_system_radio = QRadioButton("System Attacks")
        self.attack_type_group.addButton(self.attack_system_radio)
        attack_type_layout.addWidget(self.attack_system_radio)

        self.attack_network_radio = QRadioButton("Network Attacks")
        self.attack_type_group.addButton(self.attack_network_radio)
        attack_type_layout.addWidget(self.attack_network_radio)

        attack_layout.addLayout(attack_type_layout)

        # System attack options (only visible when System Attacks selected)
        self.system_options_group = QGroupBox("System Attack Options")
        self.system_options_group.setVisible(False)
        system_options_layout = QVBoxLayout(self.system_options_group)

        self.auth_check = QCheckBox("Authentication Attacks")
        self.auth_check.setChecked(True)
        system_options_layout.addWidget(self.auth_check)

        self.privesc_check = QCheckBox("Authorization/Privilege Escalation")
        self.privesc_check.setChecked(True)
        system_options_layout.addWidget(self.privesc_check)

        self.exec_check = QCheckBox("Code Execution")
        self.exec_check.setChecked(True)
        system_options_layout.addWidget(self.exec_check)

        attack_layout.addWidget(self.system_options_group)

        # Network attack options (only visible when Network Attacks selected)
        self.network_options_group = QGroupBox("Network Service Attack Options")
        self.network_options_group.setVisible(False)
        network_options_layout = QVBoxLayout(self.network_options_group)

        self.ssh_check = QCheckBox("SSH")
        self.ssh_check.setChecked(True)
        network_options_layout.addWidget(self.ssh_check)

        self.ftp_check = QCheckBox("FTP")
        self.ftp_check.setChecked(True)
        network_options_layout.addWidget(self.ftp_check)

        self.smb_check = QCheckBox("SMB")
        self.smb_check.setChecked(True)
        network_options_layout.addWidget(self.smb_check)

        self.http_check = QCheckBox("HTTP/HTTPS")
        self.http_check.setChecked(True)
        network_options_layout.addWidget(self.http_check)

        self.rdp_check = QCheckBox("RDP")
        self.rdp_check.setChecked(True)
        network_options_layout.addWidget(self.rdp_check)

        attack_layout.addWidget(self.network_options_group)

        # Connect attack type radio button signals
        self.attack_all_radio.toggled.connect(self.toggle_attack_options)
        self.attack_system_radio.toggled.connect(self.toggle_attack_options)
        self.attack_network_radio.toggled.connect(self.toggle_attack_options)

        attack_group.setLayout(attack_layout)
        left_layout.addWidget(attack_group)

        # Actions section
        actions_group = QGroupBox("Actions")
        actions_group.setStyleSheet(SECTION_STYLE)
        actions_layout = QVBoxLayout()

        # Action buttons
        recon_button = QPushButton("Run Information Gathering")
        recon_button.clicked.connect(lambda: self.start_operation("reconnaissance"))
        actions_layout.addWidget(recon_button)

        scan_button = QPushButton("Run Vulnerability Scanning")
        scan_button.clicked.connect(lambda: self.start_operation("scanning"))
        actions_layout.addWidget(scan_button)

        exploit_button = QPushButton("Run Exploitation")
        exploit_button.clicked.connect(lambda: self.start_operation("exploitation"))
        actions_layout.addWidget(exploit_button)

        full_button = QPushButton("Run Full Penetration Test")
        full_button.clicked.connect(lambda: self.start_operation("full_pentest"))
        full_button.setStyleSheet("background-color: #4CAF50; color: white; font-weight: bold;")
        actions_layout.addWidget(full_button)

        actions_group.setLayout(actions_layout)
        left_layout.addWidget(actions_group)

        # Add OpenVAS configuration section
        openvas_group = self.add_openvas_config()
        left_layout.addWidget(openvas_group)

        # Progress section
        progress_group = QGroupBox("Progress")
        progress_group.setStyleSheet(SECTION_STYLE)
        progress_layout = QVBoxLayout()

        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        progress_layout.addWidget(self.progress_bar)

        self.status_label = QLabel("Ready")
        progress_layout.addWidget(self.status_label)

        progress_group.setLayout(progress_layout)
        left_layout.addWidget(progress_group)

        # Add left panel to splitter
        content_splitter.addWidget(left_panel)

        # Right panel - Results
        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)
        right_layout.setContentsMargins(10, 10, 10, 10)

        # Results tabs
        self.results_tabs = QTabWidget()

        # Dashboard tab
        self.dashboard_tab = QWidget()
        dashboard_layout = QVBoxLayout(self.dashboard_tab)

        dashboard_header = QLabel("Penetration Test Dashboard")
        dashboard_header.setStyleSheet("font-size: 20px; font-weight: bold;")
        dashboard_header.setAlignment(Qt.AlignmentFlag.AlignCenter)
        dashboard_layout.addWidget(dashboard_header)

        # Stats row
        stats_layout = QHBoxLayout()

        # Create stat boxes
        self.hosts_box = self.create_stat_box(stats_layout, "Hosts Discovered", "0", "#4CAF50")
        self.ports_box = self.create_stat_box(stats_layout, "Open Ports", "0", "#2196F3")
        self.vulns_box = self.create_stat_box(stats_layout, "Vulnerabilities", "0", "#FFC107")
        self.exploits_box = self.create_stat_box(stats_layout, "Successful Exploits", "0", "#F44336")

        dashboard_layout.addLayout(stats_layout)

        # Findings table
        findings_group = QGroupBox("Recent Findings")
        findings_layout = QVBoxLayout(findings_group)

        self.findings_table = QTableWidget()
        self.findings_table.setColumnCount(4)
        self.findings_table.setHorizontalHeaderLabels(["Host", "Service", "Finding", "Severity"])
        self.findings_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)

        findings_layout.addWidget(self.findings_table)
        dashboard_layout.addWidget(findings_group)

        # Attack progress section
        progress_group = QGroupBox("Attack Progress")
        progress_layout = QVBoxLayout(progress_group)

        # System attacks progress
        system_label = QLabel("System Attacks")
        system_label.setStyleSheet("font-weight: bold;")
        progress_layout.addWidget(system_label)

        self.system_progress = QProgressBar()
        self.system_progress.setValue(0)
        progress_layout.addWidget(self.system_progress)

        # Network attacks progress
        network_label = QLabel("Network Attacks")
        network_label.setStyleSheet("font-weight: bold;")
        progress_layout.addWidget(network_label)

        self.network_progress = QProgressBar()
        self.network_progress.setValue(0)
        progress_layout.addWidget(self.network_progress)

        dashboard_layout.addWidget(progress_group)

        self.results_tabs.addTab(self.dashboard_tab, "Dashboard")

        # Console tab
        self.console_tab = QTextEdit()
        self.console_tab.setReadOnly(True)
        self.results_tabs.addTab(self.console_tab, "Console")

        # Results tab
        self.results_tab = QTextEdit()
        self.results_tab.setReadOnly(True)
        self.results_tabs.addTab(self.results_tab, "Results")

        # Hosts tab (will be populated dynamically)
        self.hosts_tab = QTableWidget()
        self.hosts_tab.setColumnCount(4)
        self.hosts_tab.setHorizontalHeaderLabels(["Host", "OS", "Open Ports", "Services"])
        self.hosts_tab.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.results_tabs.addTab(self.hosts_tab, "Hosts")

        # Vulnerabilities tab
        self.vulnerabilities_tab = QTableWidget()
        self.vulnerabilities_tab.setColumnCount(4)
        self.vulnerabilities_tab.setHorizontalHeaderLabels(["Host", "Port", "Service", "Vulnerability"])
        self.vulnerabilities_tab.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.results_tabs.addTab(self.vulnerabilities_tab, "Vulnerabilities")

        # Report tab
        self.report_tab = QTextEdit()
        self.report_tab.setReadOnly(True)
        self.results_tabs.addTab(self.report_tab, "Report")

        right_layout.addWidget(self.results_tabs)

        # Add right panel to splitter
        content_splitter.addWidget(right_panel)

        # Set initial splitter sizes
        content_splitter.setSizes([400, 800])

        # Status bar
        self.statusBar().showMessage("Ready")

        # Initialize logging
        self.log("Advanced Penetration Testing Suite initialized")
        self.log("Configure target and API keys, then start operations")

    def check_status(self):
        """Periodic check to keep the application running and check worker status"""
        if hasattr(self, 'worker') and self.worker is not None and self.worker.isFinished():
            # If worker is finished but not in completed list, add it
            if self.worker not in self.completed_workers:
                self.completed_workers.append(self.worker)
                print(f"Worker completed and added to history (total: {len(self.completed_workers)})")

        # Keep a maximum of 5 completed workers in history to avoid memory issues
        while len(self.completed_workers) > 5:
            self.completed_workers.pop(0)
    def create_stat_box(self, parent_layout, title, value, color):
        """Create a statistics box for the dashboard"""
        box = QGroupBox()
        box.setStyleSheet(f"QGroupBox {{ border: 2px solid {color}; border-radius: 5px; }}")

        box_layout = QVBoxLayout(box)

        title_label = QLabel(title)
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title_label.setStyleSheet("font-size: 14px;")
        box_layout.addWidget(title_label)

        value_label = QLabel(value)
        value_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        value_label.setStyleSheet(f"font-size: 24px; font-weight: bold; color: {color};")
        box_layout.addWidget(value_label)

        # Store the value label for later updates
        box.value_label = value_label

        parent_layout.addWidget(box)
        return box

    def create_toolbar(self):
        """Create the main toolbar"""
        toolbar = QToolBar("Main Toolbar")
        toolbar.setIconSize(QSize(24, 24))
        self.addToolBar(toolbar)

        # New project action
        new_action = QAction("New Project", self)
        new_action.triggered.connect(self.create_new_project)
        toolbar.addAction(new_action)

        # Save results action
        save_action = QAction("Save Results", self)
        save_action.triggered.connect(self.save_results)
        toolbar.addAction(save_action)

        # Load results action
        load_action = QAction("Load Results", self)
        load_action.triggered.connect(self.load_results)
        toolbar.addAction(load_action)

        toolbar.addSeparator()

        # Settings action
        settings_action = QAction("Settings", self)
        settings_action.triggered.connect(self.show_settings)
        toolbar.addAction(settings_action)

        # Help action
        help_action = QAction("Help", self)
        help_action.triggered.connect(self.show_help)
        toolbar.addAction(help_action)

    def toggle_target_type(self):
        """Handle target type selection change"""
        if self.target_system_radio.isChecked():
            # System target selected
            self.target_input.setPlaceholderText("e.g., 192.168.1.100")
            self.attack_system_radio.setEnabled(True)
        else:
            # Network target selected
            self.target_input.setPlaceholderText("e.g., 192.168.1.0/24")
            # Optionally switch to network attacks when network target selected
            if self.attack_system_radio.isChecked():
                self.attack_all_radio.setChecked(True)

    def toggle_attack_options(self):
        """Handle attack type selection change"""
        if self.attack_system_radio.isChecked():
            # Show system attack options, hide network options
            self.system_options_group.setVisible(True)
            self.network_options_group.setVisible(False)
        elif self.attack_network_radio.isChecked():
            # Show network attack options, hide system options
            self.system_options_group.setVisible(False)
            self.network_options_group.setVisible(True)
        else:
            # All attacks selected, hide both option groups
            self.system_options_group.setVisible(False)
            self.network_options_group.setVisible(False)

    def create_new_project(self):
        """Create a new project"""
        reply = QMessageBox.question(
            self, "New Project",
            "Are you sure you want to start a new project? Any unsaved results will be lost.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )

        if reply == QMessageBox.StandardButton.Yes:
            # Clear inputs except API keys
            self.target_input.clear()

            # Reset target and attack options
            self.target_system_radio.setChecked(True)
            self.attack_all_radio.setChecked(True)

            # Clear results
            self.results = {}
            self.console_tab.clear()
            self.results_tab.clear()
            self.hosts_tab.setRowCount(0)
            self.vulnerabilities_tab.setRowCount(0)
            self.report_tab.clear()

            # Reset dashboard
            self.hosts_box.value_label.setText("0")
            self.ports_box.value_label.setText("0")
            self.vulns_box.value_label.setText("0")
            self.exploits_box.value_label.setText("0")
            self.findings_table.setRowCount(0)
            self.system_progress.setValue(0)
            self.network_progress.setValue(0)

            # Reset progress
            self.progress_bar.setValue(0)
            self.status_label.setText("Ready")
            self.statusBar().showMessage("New project created")

            # Log
            self.log("New project created")

    def save_results(self):
        """Save current results to a file"""
        if not self.results:
            QMessageBox.warning(self, "No Results", "There are no results to save.")
            return

        filename, _ = QFileDialog.getSaveFileName(
            self, "Save Results",
            os.path.join(self.workspace, "results.json"),
            "JSON Files (*.json)"
        )

        if filename:
            try:
                with open(filename, 'w') as f:
                    json.dump(self.results, f, indent=4)
                self.statusBar().showMessage(f"Results saved to {filename}")
                self.log(f"Results saved to {filename}", "success")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Could not save results: {str(e)}")
                self.log(f"Error saving results: {str(e)}", "error")

    def load_results(self):
        """Load results from a file"""
        filename, _ = QFileDialog.getOpenFileName(
            self, "Load Results",
            self.workspace,
            "JSON Files (*.json)"
        )

        if filename:
            try:
                with open(filename, 'r') as f:
                    results = json.load(f)

                self.results = results
                self.display_results(results)
                self.statusBar().showMessage(f"Results loaded from {filename}")
                self.log(f"Results loaded from {filename}", "success")

                # Update dashboard
                self.update_dashboard(results)
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Could not load results: {str(e)}")
                self.log(f"Error loading results: {str(e)}", "error")

    def show_settings(self):
        """Show settings dialog"""
        # This would be a more detailed settings dialog
        QMessageBox.information(
            self, "Settings",
            "The settings dialog would allow you to configure various aspects of the application."
        )

    def show_help(self):
        """Show help information"""
        QMessageBox.information(
            self, "Help",
            "Advanced Penetration Testing Suite\n\n"
            "1. Select target type (System or Network)\n"
            "2. Enter your target IP or network range\n"
            "3. Select attack focus (All, System, or Network)\n"
            "4. Configure specific attack options if needed\n"
            "5. Enter your OpenAI API key for AI-guided testing\n"
            "6. Configure Caldera connection settings\n"
            "7. Select an operation to perform\n\n"
            "For detailed usage instructions, refer to the README file."
        )

    def browse_workspace(self):
        """Open directory browser to select workspace"""
        directory = QFileDialog.getExistingDirectory(
            self, "Select Workspace Directory",
            self.workspace
        )

        if directory:
            self.workspace = directory
            self.workspace_input.setText(directory)
            self.log(f"Workspace set to: {directory}")

    def start_operation(self, operation):
        """Start the specified operation"""
        # Validate inputs
        target = self.target_input.text().strip()
        if not target:
            QMessageBox.warning(self, "Input Error", "Please enter a target IP or network.")
            return

        api_key = self.api_key_input.text().strip()
        if not api_key and operation != "reconnaissance":
            QMessageBox.warning(self, "Input Error", "Please enter your OpenAI API key.")
            return

        caldera_url = self.caldera_url_input.text().strip()
        caldera_key = self.caldera_key_input.text().strip()
        workspace = self.workspace_input.text().strip()

        # Determine target type and attack focus
        target_type = "system" if self.target_system_radio.isChecked() else "network"

        if self.attack_system_radio.isChecked():
            attack_type = "system"
        elif self.attack_network_radio.isChecked():
            attack_type = "network"
        else:
            attack_type = None  # Both system and network attacks

        # Get OpenVAS configuration if enabled
        use_openvas = hasattr(self, 'use_openvas_check') and self.use_openvas_check.isChecked()
        openvas_config = None

        if use_openvas:
            openvas_config = {
                "host": self.openvas_host_input.text(),
                "port": int(self.openvas_port_input.text()),
                "username": self.openvas_username_input.text(),
                "password": self.openvas_password_input.text()
            }

        # Create workspace directory if it doesn't exist
        os.makedirs(workspace, exist_ok=True)

        # Display operation info
        operation_name = {
            "reconnaissance": "Information Gathering",
            "scanning": "Vulnerability Scanning",
            "exploitation": "Exploitation",
            "full_pentest": "Full Penetration Test"
        }.get(operation, operation)

        target_desc = f"{target} ({target_type})"
        attack_desc = f" - {attack_type.upper()} attacks" if attack_type else ""
        scanner_desc = f" using OpenVAS" if use_openvas and operation == "scanning" else ""

        self.log(f"Starting {operation_name} on {target_desc}{attack_desc}{scanner_desc}", "info")

        # Reset progress
        self.progress_bar.setValue(0)
        self.status_label.setText(f"Running {operation_name}...")

        # CRITICAL FIX: Make sure any existing worker is properly disconnected
        if hasattr(self, 'worker') and self.worker is not None:
            try:
                # Disconnect all signals
                self.worker.update_signal.disconnect()
                self.worker.progress_signal.disconnect()
                self.worker.result_signal.disconnect()
                self.worker.finished_signal.disconnect()
            except:
                # Ignore any disconnect errors
                pass

            # Terminate any existing worker
            if self.worker.isRunning():
                self.worker.terminate()
                self.worker.wait()

        # Create and start the worker thread
        self.worker = PentestWorker(
            operation=operation,
            target_type=target_type,
            target=target,
            api_key=api_key,
            caldera_url=caldera_url,
            caldera_key=caldera_key,
            workspace=workspace,
            attack_type=attack_type,
            use_openvas=use_openvas,
            openvas_config=openvas_config
        )

        # CRITICAL FIX: Store a reference to the worker to prevent garbage collection
        self.current_worker = self.worker

        # Connect signals
        self.worker.update_signal.connect(self.log)
        self.worker.progress_signal.connect(self.update_progress)
        self.worker.result_signal.connect(self.handle_results)
        self.worker.finished_signal.connect(self.operation_finished)

        # Start the worker
        self.worker.start()

        # CRITICAL FIX: Print confirmation that worker started
        print(f"Started {operation} worker thread")

    def update_progress(self, value):
        """Update the progress bar"""
        self.progress_bar.setValue(value)

    def log(self, message, msg_type="info"):
        """Add a log message to the console"""
        timestamp = time.strftime("%H:%M:%S")

        # Apply styling based on message type
        style = ""
        if msg_type == "error":
            style = ERROR_STYLE
        elif msg_type == "warning":
            style = WARNING_STYLE
        elif msg_type == "success":
            style = SUCCESS_STYLE

        formatted_message = f"<span style='color:#888888;'>[{timestamp}]</span> "
        if style:
            formatted_message += f"<span style='{style}'>{message}</span>"
        else:
            formatted_message += message

        self.console_tab.append(formatted_message)

        # Auto-scroll to bottom
        cursor = self.console_tab.textCursor()
        cursor.movePosition(cursor.MoveOperation.End)
        self.console_tab.setTextCursor(cursor)

        # Update status bar for important messages
        if msg_type in ["error", "success"]:
            self.statusBar().showMessage(message)

    def handle_results(self, results):
        """Process and display the results"""
        self.results = results
        self.display_results(results)
        self.update_dashboard(results)

        # Check if this is an exploitation result with AI recommendations
        if results.get('phase') == 'exploitation' and 'ai_recommendations' in results:
            self.display_ai_recommendations(results.get('ai_recommendations', []))

            # Show system vs network success
            if results.get('system_success'):
                self.log("System-level exploitation successful", "success")
            if results.get('network_success'):
                self.log("Network-level exploitation successful", "success")

    def display_ai_recommendations(self, recommendations):
        """Display AI-recommended attack techniques"""
        if not recommendations:
            return

        # Create a section for AI recommendations in the Results tab
        ai_section = "<h3>AI-Recommended Attack Techniques</h3><table border='1' cellpadding='5'>"
        ai_section += "<tr><th>Technique ID</th><th>Name</th><th>Attack Type</th><th>Reason</th></tr>"

        for rec in recommendations:
            technique_id = rec.get('technique_id', 'Unknown')
            name = rec.get('name', 'Unknown')
            attack_type = rec.get('attack_type', 'unknown')
            reason = rec.get('reason', '')

            # Style based on attack type
            attack_type_style = "color:blue" if attack_type.lower() == "network" else "color:green"

            ai_section += f"<tr><td>{technique_id}</td><td>{name}</td>"
            ai_section += f"<td style='{attack_type_style}'>{attack_type.upper()}</td>"
            ai_section += f"<td>{reason}</td></tr>"

        ai_section += "</table>"

        # Add this to the Report tab
        current_report = self.report_tab.toHtml()
        if "<h2>AI Recommendations</h2>" not in current_report:
            self.report_tab.append("<h2>AI Recommendations</h2>")
            self.report_tab.append(ai_section)
    def display_results(self, results):
        """Display the results in the appropriate tabs"""
        # Set formatted JSON in results tab
        self.results_tab.setText(json.dumps(results, indent=4))

        # Process for hosts tab
        self.hosts_tab.setRowCount(0)  # Clear existing rows

        # Different result formats based on the phase
        if "network_summary" in results:  # Reconnaissance results
            hosts = results.get("network_summary", {}).get("live_hosts", [])
            host_details = results.get("host_details", {})

            for i, host in enumerate(hosts):
                self.hosts_tab.insertRow(i)
                self.hosts_tab.setItem(i, 0, QTableWidgetItem(host))

                details = host_details.get(host, {})
                os_info = details.get("os", "Unknown")
                self.hosts_tab.setItem(i, 1, QTableWidgetItem(os_info))

                open_ports = ", ".join(map(str, details.get("open_ports", [])))
                self.hosts_tab.setItem(i, 2, QTableWidgetItem(open_ports))

                services = []
                for port, service_info in details.get("services", {}).items():
                    service_name = service_info.get("name", "unknown")
                    service_version = service_info.get("version", "")
                    services.append(f"{service_name} ({port})")

                self.hosts_tab.setItem(i, 3, QTableWidgetItem(", ".join(services)))

        elif "scan_results" in results:  # Scanning results
            scan_results = results.get("scan_results", [])

            for i, target in enumerate(scan_results):
                host = target.get("host", "")
                self.hosts_tab.insertRow(i)
                self.hosts_tab.setItem(i, 0, QTableWidgetItem(host))
                self.hosts_tab.setItem(i, 1, QTableWidgetItem(target.get("os_type", "Unknown")))

                # Extract services and ports
                services = target.get("services", {})
                self.hosts_tab.setItem(i, 2, QTableWidgetItem(", ".join(map(str, services.values()))))
                self.hosts_tab.setItem(i, 3, QTableWidgetItem(", ".join(services.keys())))

                # Process vulnerabilities
                vulns = target.get("vulnerabilities", {})

                for port, vuln_details in vulns.items():
                    for vuln in vuln_details.get("vulnerabilities", []):
                        row = self.vulnerabilities_tab.rowCount()
                        self.vulnerabilities_tab.insertRow(row)

                        self.vulnerabilities_tab.setItem(row, 0, QTableWidgetItem(host))
                        self.vulnerabilities_tab.setItem(row, 1, QTableWidgetItem(str(port)))
                        self.vulnerabilities_tab.setItem(row, 2, QTableWidgetItem(vuln_details.get("service", "")))
                        self.vulnerabilities_tab.setItem(row, 3, QTableWidgetItem(vuln.get("script", "")))

        # Find the part where you display exploitation results
        if "phases" in results and "exploitation" in results["phases"]:
            exploitation = results["phases"]["exploitation"]
            exploit_count = len(exploitation.get("successful_exploits", []))

            report_html = ""

            # Display detailed exploitation results
            if exploit_count > 0:
                report_html += "<h3>Successful Exploits</h3>"
                report_html += "<table border='1' cellpadding='5'>"
                report_html += "<tr><th>Target</th><th>Attack Types</th><th>Techniques Used</th></tr>"

                for exploit in exploitation.get("successful_exploits", []):
                    target = exploit.get('target', {}).get('host', 'unknown')

                    # Show which attack types were successful
                    attack_types = []
                    if exploit.get('system_success'):
                        attack_types.append("System")
                    if exploit.get('network_success'):
                        attack_types.append("Network")
                    attack_types_str = ", ".join(attack_types) if attack_types else "Unknown"

                    # Show which abilities were used
                    system_abilities = exploit.get('system_abilities', [])
                    network_abilities = exploit.get('network_abilities', [])

                    abilities_html = "<ul>"
                    if system_abilities:
                        abilities_html += "<li><b>System techniques:</b><ul>"
                        for ability in system_abilities:
                            abilities_html += f"<li>{ability}</li>"
                        abilities_html += "</ul></li>"

                    if network_abilities:
                        abilities_html += "<li><b>Network techniques:</b><ul>"
                        for ability in network_abilities:
                            abilities_html += f"<li>{ability}</li>"
                        abilities_html += "</ul></li>"

                    abilities_html += "</ul>"

                    report_html += f"<tr><td>{target}</td><td>{attack_types_str}</td><td>{abilities_html}</td></tr>"

                report_html += "</table>"

        # Display report if available
        if "final_report" in results:
            report = results.get("final_report", {})

            report_html = "<h2>Penetration Test Report</h2>"

            # Summary
            summary = report.get("summary", {})
            if summary:
                report_html += "<h3>Summary</h3>"
                report_html += "<table border='1' cellpadding='5' style='border-collapse: collapse;'>"
                for key, value in summary.items():
                    report_html += f"<tr><td><b>{key.replace('_', ' ').title()}</b></td><td>{value}</td></tr>"
                report_html += "</table>"

            # Key findings
            findings = report.get("key_findings", [])
            if findings:
                report_html += "<h3>Key Findings</h3>"
                report_html += "<ul>"
                for finding in findings:
                    report_html += f"<li><b>{finding.get('title', '')}</b>: {finding.get('description', '')}</li>"
                report_html += "</ul>"

            # Recommendations
            recommendations = report.get("recommendations", [])
            if recommendations:
                report_html += "<h3>Recommendations</h3>"
                report_html += "<ul>"
                for rec in recommendations:
                    report_html += f"<li><b>{rec.get('title', '')}</b>: {rec.get('description', '')}</li>"
                report_html += "</ul>"

            self.report_tab.setHtml(report_html)

    def update_dashboard(self, results):
        """Update the dashboard with new results"""
        if not results:
            return

        # Extract hosts, vulnerabilities and exploits counts
        hosts_count = 0
        ports_count = 0
        vuln_count = 0
        exploit_count = 0

        findings = []

        # Process reconnaissance results
        if "network_summary" in results:
            hosts = results.get("network_summary", {}).get("live_hosts", [])
            hosts_count = len(hosts)

            # Process host details for open ports
            host_details = results.get("host_details", {})
            for host, details in host_details.items():
                ports = details.get("open_ports", [])
                ports_count += len(ports)

        # Process scanning results
        if "scan_results" in results:
            scan_results = results.get("scan_results", [])

            for target in scan_results:
                host = target.get("host", "")

                # Add to hosts count if not already counted
                if "network_summary" not in results:
                    hosts_count += 1

                # Count vulnerabilities
                vulnerabilities = target.get("vulnerabilities", {})
                for port, vuln_details in vulnerabilities.items():
                    vuln_list = vuln_details.get("vulnerabilities", [])
                    vuln_count += len(vuln_list)

                    for vuln in vuln_list:
                        # Determine severity
                        severity = "Medium"  # Default
                        output = vuln.get("output", "").lower()

                        if "critical" in output:
                            severity = "Critical"
                        elif "high" in output:
                            severity = "High"

                        # Add to findings
                        findings.append({
                            "host": host,
                            "service": vuln_details.get("service", ""),
                            "finding": vuln.get("script", ""),
                            "severity": severity
                        })

        # Process exploitation results
        if "phases" in results and "exploitation" in results["phases"]:
            exploitation = results["phases"]["exploitation"]
            exploit_count = len(exploitation.get("successful_exploits", []))

            # Add successful exploits to findings
            for exploit in exploitation.get("successful_exploits", []):
                findings.append({
                    "host": exploit.get("target", {}).get("host", ""),
                    "service": exploit.get("target", {}).get("service", ""),
                    "finding": f"Successful exploit: {exploit.get('technique', '')}",
                    "severity": "Critical"
                })
        elif "successful_exploits" in results:
            exploit_count = len(results.get("successful_exploits", []))

        # Update stat boxes
        self.hosts_box.value_label.setText(str(hosts_count))
        self.ports_box.value_label.setText(str(ports_count))
        self.vulns_box.value_label.setText(str(vuln_count))
        self.exploits_box.value_label.setText(str(exploit_count))

        # Populate findings table
        self.findings_table.setRowCount(len(findings))
        for i, finding in enumerate(findings):
            self.findings_table.setItem(i, 0, QTableWidgetItem(finding["host"]))
            self.findings_table.setItem(i, 1, QTableWidgetItem(finding["service"]))
            self.findings_table.setItem(i, 2, QTableWidgetItem(finding["finding"]))

            severity_item = QTableWidgetItem(finding["severity"])
            if finding["severity"] == "Critical":
                severity_item.setBackground(QColor("#d9534f"))
                severity_item.setForeground(QColor("white"))
            elif finding["severity"] == "High":
                severity_item.setBackground(QColor("#f0ad4e"))
            elif finding["severity"] == "Medium":
                severity_item.setBackground(QColor("#5bc0de"))
            elif finding["severity"] == "Low":
                severity_item.setBackground(QColor("#5cb85c"))

            self.findings_table.setItem(i, 3, severity_item)

        # Update progress bars
        if "phases" in results and "attack_plan" in results["phases"]:
            attack_plan = results["phases"]["attack_plan"]

            system_attacks = attack_plan.get("system_attacks", [])
            network_attacks = attack_plan.get("network_attacks", [])

            # Simple way to show progress (would be more sophisticated in real implementation)
            if system_attacks:
                self.system_progress.setValue(50)  # Show progress based on more detailed metrics in real app

            if network_attacks:
                self.network_progress.setValue(50)  # Show progress based on more detailed metrics in real app

        if "phases" in results and "exploitation" in results["phases"]:
            # If exploitation phase is complete, show higher progress
            self.system_progress.setValue(75)
            self.network_progress.setValue(75)

            # If successful exploits, show even higher progress
            if exploit_count > 0:
                self.system_progress.setValue(100)
                self.network_progress.setValue(100)

    def add_openvas_config(self):
        """Add OpenVAS configuration to the UI"""
        # Create OpenVAS configuration group
        openvas_config_group = QGroupBox("OpenVAS Scanner")
        openvas_config_group.setStyleSheet(SECTION_STYLE)
        openvas_config_layout = QFormLayout()

        # OpenVAS toggle
        self.use_openvas_check = QCheckBox("Use OpenVAS for vulnerability scanning")
        self.use_openvas_check.stateChanged.connect(self.toggle_openvas_config)
        openvas_config_layout.addRow(self.use_openvas_check)

        # OpenVAS configuration
        self.openvas_config_widget = QWidget()
        openvas_layout = QFormLayout(self.openvas_config_widget)

        self.openvas_host_input = QLineEdit("localhost")
        openvas_layout.addRow("OpenVAS Host:", self.openvas_host_input)

        self.openvas_port_input = QLineEdit("9390")
        openvas_layout.addRow("OpenVAS Port:", self.openvas_port_input)

        self.openvas_username_input = QLineEdit("admin")
        openvas_layout.addRow("OpenVAS Username:", self.openvas_username_input)

        self.openvas_password_input = QLineEdit("admin")
        self.openvas_password_input.setEchoMode(QLineEdit.EchoMode.Password)
        openvas_layout.addRow("OpenVAS Password:", self.openvas_password_input)

        # Add test connection button
        self.test_openvas_button = QPushButton("Test Connection")
        self.test_openvas_button.clicked.connect(self.test_openvas_connection)
        openvas_layout.addRow(self.test_openvas_button)

        # Add configurations to main layout
        self.openvas_config_widget.setLayout(openvas_layout)
        openvas_config_layout.addRow(self.openvas_config_widget)
        openvas_config_group.setLayout(openvas_config_layout)

        # Initially hide the OpenVAS configuration
        self.openvas_config_widget.setVisible(False)

        return openvas_config_group

    def toggle_openvas_config(self, state):
        """Handle OpenVAS checkbox state change"""
        self.openvas_config_widget.setVisible(state == Qt.CheckState.Checked.value)

    def test_openvas_connection(self):
        """Test the OpenVAS connection with provided settings"""
        try:
            host = self.openvas_host_input.text()
            port = int(self.openvas_port_input.text())
            username = self.openvas_username_input.text()
            password = self.openvas_password_input.text()

            # Show a message that we're testing
            self.log("Testing connection to OpenVAS...", "info")

            # Create a scanner just for testing
            from openvas_scanner import OpenVASScanner
            scanner = OpenVASScanner()
            scanner.configure_openvas(host, port, username, password)

            if scanner.openvas_available:
                QMessageBox.information(self, "OpenVAS Connection", "Successfully connected to OpenVAS!")
                self.log("Successfully connected to OpenVAS", "success")
            else:
                QMessageBox.warning(self, "OpenVAS Connection",
                                    "Failed to connect to OpenVAS. Please check your settings and make sure OpenVAS is running.")
                self.log("Failed to connect to OpenVAS", "error")
        except Exception as e:
            QMessageBox.critical(self, "OpenVAS Connection Error", f"Error testing connection: {str(e)}")
            self.log(f"Error testing OpenVAS connection: {str(e)}", "error")

    def operation_finished(self):
        """Handle operation completion"""
        # CRITICAL: Print confirmation that we received the finished signal
        print("Worker thread finished signal received")

        self.status_label.setText("Operation completed")
        self.log("Operation completed", "success")

        # CRITICAL: Don't delete the worker here - keep it for reference
        # Simply mark it as done
        if hasattr(self, 'worker') and self.worker is not None:
            self.worker.setObjectName("completed_worker")

        # Update the UI to show it's ready for another operation
        self.progress_bar.setValue(100)

        # CRITICAL: Make sure we keep the application running!
        # PyQt sometimes needs a small task to prevent immediate termination
        QTimer.singleShot(100, lambda: self.statusBar().showMessage("Ready for next operation"))


if __name__ == "__main__":
    app = QApplication(sys.argv)

    # Set application style
    app.setStyle("Fusion")

    window = PenetrationTestingGUI()
    window.show()

    sys.exit(app.exec())