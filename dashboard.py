import sys
from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QTableWidget, QTableWidgetItem, QHeaderView,
    QGroupBox, QPushButton, QProgressBar
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor


class DashboardWidget(QWidget):
    """Dashboard widget to show penetration test results overview (without charts)"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.initUI()

    def initUI(self):
        """Initialize the dashboard UI"""
        main_layout = QVBoxLayout(self)

        # Header
        header_label = QLabel("Penetration Test Dashboard")
        header_label.setStyleSheet("font-size: 20px; font-weight: bold;")
        header_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        main_layout.addWidget(header_label)

        # Stats row
        stats_layout = QHBoxLayout()

        # Create stat boxes
        self.hosts_box = self.create_stat_box(stats_layout, "Hosts Discovered", "0", "#4CAF50")
        self.ports_box = self.create_stat_box(stats_layout, "Open Ports", "0", "#2196F3")
        self.vulns_box = self.create_stat_box(stats_layout, "Vulnerabilities", "0", "#FFC107")
        self.exploits_box = self.create_stat_box(stats_layout, "Successful Exploits", "0", "#F44336")

        main_layout.addLayout(stats_layout)

        # Recent findings table
        findings_group = QGroupBox("Recent Findings")
        findings_layout = QVBoxLayout(findings_group)

        self.findings_table = QTableWidget()
        self.findings_table.setColumnCount(4)
        self.findings_table.setHorizontalHeaderLabels(["Host", "Service", "Finding", "Severity"])
        self.findings_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)

        findings_layout.addWidget(self.findings_table)
        main_layout.addWidget(findings_group)

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

        main_layout.addWidget(progress_group)

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

    def reset_dashboard(self):
        """Reset the dashboard to initial state"""
        # Clear findings table
        self.findings_table.setRowCount(0)

        # Reset progress bars
        self.system_progress.setValue(0)
        self.network_progress.setValue(0)

    def update_dashboard(self, results):
        """Update the dashboard with new results"""
        # Reset first
        self.reset_dashboard()

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


# Example usage if run directly
if __name__ == "__main__":
    app = QApplication(sys.argv)

    # Set application style
    app.setStyle("Fusion")

    window = DashboardWidget()
    window.show()

    sys.exit(app.exec())