import os
import json
import gc  # For garbage collection
import sys
import traceback
from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QGroupBox,
    QFormLayout, QTabWidget, QMessageBox,
    QTextEdit, QSplitter, QToolBar, QStatusBar,
    QFileDialog, QProgressBar, QApplication
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer, QSize, QCoreApplication, QMutex, QMutexLocker
from PyQt6.QtGui import QIcon, QFont, QAction

from .console_widget import ConsoleWidget
from ai_controller import AIPentestController


class SafeThread(QThread):
    """A thread class that implements better error handling and safe termination"""
    # Define signals
    update_signal = pyqtSignal(str, str)  # (message, type)
    finished_signal = pyqtSignal()
    error_signal = pyqtSignal(str)  # For reporting errors

    def __init__(self):
        super().__init__()
        self.mutex = QMutex()
        self.running = True
        self.should_terminate = False

    def stop(self):
        """Safely request thread termination"""
        with QMutexLocker(self.mutex):
            self.running = False
            self.should_terminate = True

    def is_running(self):
        """Check if thread should continue running"""
        with QMutexLocker(self.mutex):
            return self.running and not self.should_terminate

    def run(self):
        """Override in subclass"""
        pass


class PentestThread(SafeThread):
    """Thread for running the penetration test without blocking the UI."""

    def __init__(self, controller, mode="start", user_input=""):
        super().__init__()
        self.controller = controller
        self.mode = mode  # 'start' or 'continue'
        self.user_input = user_input

    def run(self):
        """Run the penetration test."""
        try:
            # Create local copies to avoid thread safety issues
            mode = self.mode
            user_input = self.user_input
            controller = self.controller

            if not self.is_running():
                return

            # Instead of directly calling controller methods, create a safe way to interact
            if mode == "start":
                # Just start the penetration test - it will continue automatically
                controller.start_pentest()
            elif mode == "continue":
                # This is now only needed if the user wants to manually input something
                controller.continue_pentest(user_input)
        except Exception as e:
            error_traceback = traceback.format_exc()
            self.error_signal.emit(f"Error in penetration test: {str(e)}")
            print(f"Thread error: {error_traceback}", file=sys.stderr)
        finally:
            self.finished_signal.emit()


class AIPentestGUI(QMainWindow):
    """Main window for the AI-guided Penetration Testing GUI."""

    def __init__(self):
        super().__init__()

        # Initialize state variables
        self.api_key = "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"
        self.target_ip = ""
        self.controller = None
        self.pentest_thread = None
        self.exit_requested = False

        # Install exception hook to catch unhandled exceptions
        sys.excepthook = self.excepthook

        # Set window properties
        self.setWindowTitle("AI-Guided Penetration Testing")
        self.setGeometry(100, 100, 1200, 800)

        # Create the UI
        self.create_ui()

        # Status bar for messages
        self.statusBar().showMessage("Ready")

        # Start a timer to periodically update the status bar
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_status)
        self.timer.start(5000)  # 5 seconds

    def excepthook(self, exc_type, exc_value, exc_traceback):
        """Custom exception hook to handle unhandled exceptions"""
        error_msg = ''.join(traceback.format_exception(exc_type, exc_value, exc_traceback))
        print(f"Unhandled exception: {error_msg}", file=sys.stderr)
        # Try to log to console if possible
        try:
            if hasattr(self, 'console'):
                self.console.append_text(f"CRITICAL ERROR: {str(exc_value)}", "error")
        except:
            pass
        # Show error dialog if GUI is available
        try:
            QMessageBox.critical(self, "Critical Error",
                                 f"An unhandled exception occurred:\n{str(exc_value)}\n\nSee console for details.")
        except:
            pass
        # Call the default handler
        sys.__excepthook__(exc_type, exc_value, exc_traceback)

    def create_ui(self):
        """Create the main UI components."""
        # Main widget
        main_widget = QWidget()
        self.setCentralWidget(main_widget)

        # Main layout
        main_layout = QVBoxLayout(main_widget)

        # Split the window into configuration and console sections
        splitter = QSplitter(Qt.Orientation.Vertical)
        main_layout.addWidget(splitter)

        # Configuration section
        config_widget = QWidget()
        config_layout = QVBoxLayout(config_widget)

        # Create configuration groups
        self.create_config_group(config_layout)
        self.create_tools_group(config_layout)
        self.create_actions_group(config_layout)

        # Add configuration widget to splitter
        splitter.addWidget(config_widget)

        # Console section
        self.console = ConsoleWidget()
        self.console.command_submitted.connect(self.process_user_command)
        splitter.addWidget(self.console)

        # Set initial splitter sizes
        splitter.setSizes([200, 600])

        # Create toolbar
        self.create_toolbar()

        # Welcome message
        self.console.append_text("Welcome to the AI-Guided Penetration Testing Tool!", "system")
        self.console.append_text("Configure the target and API key, then start the penetration test.", "system")

    def create_config_group(self, parent_layout):
        """Create the configuration group."""
        config_group = QGroupBox("Configuration")
        config_layout = QFormLayout()

        # Target IP
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("e.g., 192.168.1.100")
        config_layout.addRow("Target IP:", self.target_input)

        # API Key
        self.api_key_input = QLineEdit()
        self.api_key_input.setPlaceholderText("Enter your OpenAI API key")
        self.api_key_input.setEchoMode(QLineEdit.EchoMode.Password)
        if self.api_key:
            self.api_key_input.setText(self.api_key)
        config_layout.addRow("OpenAI API Key:", self.api_key_input)

        # Workspace directory
        workspace_layout = QHBoxLayout()
        self.workspace_input = QLineEdit("./workspace")
        workspace_layout.addWidget(self.workspace_input)

        browse_button = QPushButton("Browse...")
        browse_button.clicked.connect(self.browse_workspace)
        workspace_layout.addWidget(browse_button)

        config_layout.addRow("Workspace:", workspace_layout)

        # Set layout for group
        config_group.setLayout(config_layout)
        parent_layout.addWidget(config_group)

    def create_tools_group(self, parent_layout):
        """Create the tools group."""
        tools_group = QGroupBox("Tools")
        tools_layout = QFormLayout()

        # Metasploit connection
        msf_layout = QHBoxLayout()
        self.msf_host = QLineEdit("127.0.0.1")
        self.msf_port = QLineEdit("55552")
        self.msf_port.setMaximumWidth(60)
        msf_layout.addWidget(self.msf_host)
        msf_layout.addWidget(QLabel(":"))
        msf_layout.addWidget(self.msf_port)

        # Test connection button
        test_msf_button = QPushButton("Test")
        test_msf_button.setMaximumWidth(60)
        test_msf_button.clicked.connect(lambda: self.test_connection("metasploit"))
        msf_layout.addWidget(test_msf_button)

        tools_layout.addRow("Metasploit RPC:", msf_layout)

        # CALDERA connection
        caldera_layout = QHBoxLayout()
        self.caldera_url = QLineEdit("http://localhost:8888")
        self.caldera_key = QLineEdit("ADMIN123")
        caldera_layout.addWidget(self.caldera_url)
        caldera_layout.addWidget(QLabel("Key:"))
        caldera_layout.addWidget(self.caldera_key)

        # Test connection button
        test_caldera_button = QPushButton("Test")
        test_caldera_button.setMaximumWidth(60)
        test_caldera_button.clicked.connect(lambda: self.test_connection("caldera"))
        caldera_layout.addWidget(test_caldera_button)

        tools_layout.addRow("CALDERA:", caldera_layout)

        # Set layout for group
        tools_group.setLayout(tools_layout)
        parent_layout.addWidget(tools_group)

    def create_actions_group(self, parent_layout):
        """Create the actions group."""
        actions_group = QGroupBox("Actions")
        actions_layout = QHBoxLayout()

        # Start button
        self.start_button = QPushButton("Start Penetration Test")
        self.start_button.clicked.connect(self.start_penetration_test)
        actions_layout.addWidget(self.start_button)

        # Continue button
        self.continue_button = QPushButton("Continue")
        self.continue_button.clicked.connect(self.continue_penetration_test)
        self.continue_button.setEnabled(False)
        actions_layout.addWidget(self.continue_button)

        # Stop button
        self.stop_button = QPushButton("Stop")
        self.stop_button.clicked.connect(self.stop_penetration_test)
        self.stop_button.setEnabled(False)
        actions_layout.addWidget(self.stop_button)

        # Set layout for group
        actions_group.setLayout(actions_layout)
        parent_layout.addWidget(actions_group)

    def create_toolbar(self):
        """Create the toolbar."""
        toolbar = QToolBar("Main Toolbar")
        toolbar.setIconSize(QSize(24, 24))
        self.addToolBar(toolbar)

        # New test action
        new_action = QAction("New Test", self)
        new_action.triggered.connect(self.new_test)
        toolbar.addAction(new_action)

        # Save results action
        save_action = QAction("Save Results", self)
        save_action.triggered.connect(self.save_results)
        toolbar.addAction(save_action)

        # Settings action
        settings_action = QAction("Settings", self)
        settings_action.triggered.connect(self.show_settings)
        toolbar.addAction(settings_action)

        # Help action
        help_action = QAction("Help", self)
        help_action.triggered.connect(self.show_help)
        toolbar.addAction(help_action)

    def browse_workspace(self):
        """Open directory browser to select workspace."""
        directory = QFileDialog.getExistingDirectory(
            self, "Select Workspace Directory",
            self.workspace_input.text()
        )

        if directory:
            self.workspace_input.setText(directory)
            self.console.append_text(f"Workspace set to: {directory}", "system")

    def test_connection(self, tool):
        """Test connection to a tool."""
        try:
            if tool == "metasploit":
                from tool_interfaces.metasploit_interface import MetasploitInterface

                host = self.msf_host.text()
                port = int(self.msf_port.text())

                self.console.append_text(f"Testing connection to Metasploit RPC at {host}:{port}...", "system")

                msf = MetasploitInterface(host=host, port=port)
                if msf.authenticated:
                    self.console.append_text("Successfully connected to Metasploit RPC!", "success")
                else:
                    self.console.append_text("Failed to authenticate with Metasploit RPC.", "error")

            elif tool == "caldera":
                from tool_interfaces.caldera_interface import CalderaInterface

                url = self.caldera_url.text()
                key = self.caldera_key.text()

                self.console.append_text(f"Testing connection to CALDERA at {url}...", "system")

                caldera = CalderaInterface(api_url=url, api_key=key)
                if caldera.test_connection():
                    self.console.append_text("Successfully connected to CALDERA!", "success")
                else:
                    self.console.append_text("Failed to connect to CALDERA.", "error")

        except Exception as e:
            error_traceback = traceback.format_exc()
            self.console.append_text(f"Error testing connection to {tool}: {str(e)}", "error")
            print(f"Connection test error: {error_traceback}", file=sys.stderr)

    def safe_output_callback(self, message, source=None):
        """Safely handle output callbacks to prevent crashes"""
        # Ensure we're on the main thread
        if QThread.currentThread() is not QCoreApplication.instance().thread():
            # We're in a worker thread, use signals/slots
            try:
                # If we have a thread with update_signal, use it
                if hasattr(self, 'pentest_thread') and self.pentest_thread:
                    self.pentest_thread.update_signal.emit(message, source or "system")
                else:
                    # Otherwise, use a timer to execute on main thread
                    QTimer.singleShot(0, lambda: self.direct_output_callback(message, source))
            except Exception as e:
                print(f"Error in safe_output_callback: {str(e)}", file=sys.stderr)
        else:
            # We're already on the main thread
            self.direct_output_callback(message, source)

    def direct_output_callback(self, message, source=None):
        """Actually update the UI with the message"""
        try:
            # If source is directly provided, use it
            if source is not None:
                # Check for duplicated AI prefix and fix it
                if source == "ai" and message.startswith("🤖 AI:"):
                    # Remove the redundant prefix
                    message = message.replace("🤖 AI:", "", 1).strip()

                self.console.append_text(message, source)
                return

            # Otherwise, determine the source based on message prefix
            if message.startswith("🤖 AI:"):
                source = "ai"
                # Remove the prefix for cleaner display
                message = message[6:].strip()
            elif message.startswith("❌ ERROR:"):
                source = "error"
                message = message[9:].strip()
            elif message.startswith("✅"):
                source = "success"
            elif message.startswith("⚠️"):
                source = "warning"
            elif message.startswith("🔧 EXECUTING"):
                source = "system"
            elif message.startswith("📋 RESULT:"):
                source = "system"
            else:
                source = "system"

            self.console.append_text(message, source)

            # Process events to ensure UI updates
            QApplication.processEvents()

        except Exception as e:
            print(f"Error updating console: {str(e)}", file=sys.stderr)

    def process_user_command(self, command):
        """Process a command submitted by the user."""
        if command.startswith("run "):
            # Direct session command handling
            actual_command = command[4:].strip()
            if self.controller and self.controller.session_active:
                session_id = self.controller.session_info.get('id', '1')
                formatted_command = f"sessions -i {session_id} -c '{actual_command}'"
                result = self.controller.metasploit.execute_command(formatted_command)
                self.console.append_text(f"Result: {result}", "system")
                return

        # Default behavior for other commands
        if self.controller and self.continue_button.isEnabled():
            # If a test is in progress, send the command to the controller
            self.continue_penetration_test(command)
        else:
            self.console.append_text("No active penetration test. Start a test first.", "error")

    def start_penetration_test(self):
        """Start the penetration test."""
        # Validate inputs
        target_ip = self.target_input.text().strip()
        if not target_ip:
            QMessageBox.warning(self, "Input Error", "Please enter a target IP.")
            return

        api_key = self.api_key_input.text().strip()
        if not api_key:
            QMessageBox.warning(self, "Input Error", "Please enter your OpenAI API key.")
            return

        # Update state
        self.target_ip = target_ip
        self.api_key = api_key

        try:
            # Clean up any existing controller
            if self.controller:
                try:
                    self.controller.stop_pentest()
                except:
                    pass
                self.controller = None

            # Initialize the controller with our safe callback
            self.controller = AIPentestController(
                api_key=api_key,
                target_ip=target_ip,
                output_callback=self.safe_output_callback
            )

            # Update UI
            self.start_button.setEnabled(False)
            self.continue_button.setEnabled(False)
            self.stop_button.setEnabled(True)
            self.statusBar().showMessage("Penetration test running...")

            # Clear console and add start message
            self.console.clear_console()
            self.console.append_text("Starting AI-guided penetration test...", "system")
            self.console.append_text(f"Target: {target_ip}", "system")

            # Clean up any existing thread
            self.cleanup_thread()

            # Create a new thread for the start operation
            self.pentest_thread = PentestThread(self.controller, mode="start")
            self.pentest_thread.update_signal.connect(self.direct_output_callback)
            self.pentest_thread.error_signal.connect(lambda msg: self.direct_output_callback(msg, "error"))
            self.pentest_thread.finished_signal.connect(self.on_pentest_thread_finished)

            # Start the thread with QTimer to prevent immediate segfaults
            QTimer.singleShot(100, self.pentest_thread.start)

        except Exception as e:
            error_traceback = traceback.format_exc()
            self.console.append_text(f"Error initializing penetration test: {str(e)}", "error")
            print(f"Start test error: {error_traceback}", file=sys.stderr)
            self.start_button.setEnabled(True)

    def cleanup_thread(self):
        """Safely clean up any existing thread"""
        if hasattr(self, 'pentest_thread') and self.pentest_thread:
            try:
                # Disconnect signals to prevent callbacks during cleanup
                try:
                    self.pentest_thread.update_signal.disconnect()
                except:
                    pass
                try:
                    self.pentest_thread.error_signal.disconnect()
                except:
                    pass
                try:
                    self.pentest_thread.finished_signal.disconnect()
                except:
                    pass

                # Request thread termination
                self.pentest_thread.stop()

                # Wait for it to finish (with timeout)
                if not self.pentest_thread.wait(1000):  # Wait up to 1 second
                    self.pentest_thread.terminate()
                    self.pentest_thread.wait(500)

                # Clean up reference and force it to be deallocated
                self.pentest_thread.deleteLater()
                self.pentest_thread = None

                # Force garbage collection
                gc.collect()
            except Exception as e:
                print(f"Error cleaning up thread: {str(e)}", file=sys.stderr)

    def continue_penetration_test(self, user_input=""):
        """Continue the penetration test."""
        if not self.controller:
            QMessageBox.warning(self, "Error", "No active penetration test.")
            return

        try:
            # Clean up any existing thread
            self.cleanup_thread()

            # Create a new thread for continued interaction
            self.pentest_thread = PentestThread(self.controller, mode="continue", user_input=user_input)
            self.pentest_thread.update_signal.connect(self.direct_output_callback)
            self.pentest_thread.error_signal.connect(lambda msg: self.direct_output_callback(msg, "error"))
            self.pentest_thread.finished_signal.connect(self.on_pentest_thread_finished)

            # Update UI
            self.start_button.setEnabled(False)
            self.continue_button.setEnabled(False)
            self.stop_button.setEnabled(True)
            self.statusBar().showMessage("Continuing penetration test...")

            # Add continue message
            if user_input:
                self.console.append_text("Continuing with user input...", "system")
            else:
                self.console.append_text("Continuing penetration test...", "system")

            # Start the thread
            self.pentest_thread.start()
        except Exception as e:
            error_traceback = traceback.format_exc()
            self.console.append_text(f"Error continuing penetration test: {str(e)}", "error")
            print(f"Continue test error: {error_traceback}", file=sys.stderr)
            # Re-enable continue button for retry
            self.continue_button.setEnabled(True)

    def stop_penetration_test(self):
        """Stop the penetration test."""
        try:
            # First, terminate any running thread
            self.cleanup_thread()

            # Then clean up the controller resources
            if self.controller:
                try:
                    self.controller.stop_pentest()
                    self.console.append_text("Penetration test stopped.", "system")
                except Exception as e:
                    self.console.append_text(f"Error stopping penetration test: {str(e)}", "error")

            # Update UI
            self.start_button.setEnabled(True)
            self.continue_button.setEnabled(False)
            self.stop_button.setEnabled(False)
            self.statusBar().showMessage("Penetration test stopped.")
        except Exception as e:
            error_traceback = traceback.format_exc()
            self.console.append_text(f"Error stopping penetration test: {str(e)}", "error")
            print(f"Stop test error: {error_traceback}", file=sys.stderr)

    def on_pentest_thread_finished(self):
        """Handle completion of the pentest thread."""
        # Thread safety check
        if not hasattr(self, 'pentest_thread') or self.pentest_thread is None:
            return

        try:
            # Don't disconnect signals here as thread might still be emitting

            # Clean up thread reference - but don't terminate it forcibly
            # The thread has already finished running its task
            self.pentest_thread.deleteLater()
            self.pentest_thread = None

            # Force garbage collection
            gc.collect()

            # Update UI
            self.start_button.setEnabled(True)
            self.continue_button.setEnabled(True)
            self.stop_button.setEnabled(True)  # Keep stop enabled as the test is still active
            self.statusBar().showMessage("Penetration test paused - waiting for next action.")

            # Add completion message
            self.console.append_text("AI is waiting for your next instruction.", "system")

            # Process pending events to ensure UI updates
            QApplication.processEvents()
        except Exception as e:
            error_traceback = traceback.format_exc()
            print(f"Thread finished error: {error_traceback}", file=sys.stderr)
            # Try to recover UI state
            self.start_button.setEnabled(True)
            self.continue_button.setEnabled(True)
            self.stop_button.setEnabled(False)

    def new_test(self):
        """Start a new test by clearing current state."""
        # Stop current test if running
        if self.controller:
            self.stop_penetration_test()

        # Reset state
        self.controller = None
        self.console.clear_console()
        self.console.append_text("Ready to start a new penetration test.", "system")
        self.statusBar().showMessage("Ready for new test.")

        # Update UI
        self.start_button.setEnabled(True)
        self.continue_button.setEnabled(False)
        self.stop_button.setEnabled(False)

    def save_results(self):
        """Save console output to a file."""
        filename, _ = QFileDialog.getSaveFileName(
            self, "Save Results",
            os.path.join(self.workspace_input.text(), "pentest_results.txt"),
            "Text Files (*.txt)"
        )

        if filename:
            try:
                with open(filename, 'w') as f:
                    f.write(self.console.output_display.toPlainText())
                self.statusBar().showMessage(f"Results saved to {filename}")
                self.console.append_text(f"Results saved to {filename}", "success")
            except Exception as e:
                self.console.append_text(f"Error saving results: {str(e)}", "error")

    def show_settings(self):
        """Show settings dialog."""
        QMessageBox.information(
            self, "Settings",
            "Settings dialog would allow configuration of tool paths, timeouts, etc."
        )

    def show_help(self):
        """Show help information."""
        QMessageBox.information(
            self, "Help",
            "AI-Guided Penetration Testing Tool\n\n"
            "1. Enter the target IP address\n"
            "2. Enter your OpenAI API key\n"
            "3. Verify tool connections (Metasploit, CALDERA)\n"
            "4. Click 'Start Penetration Test'\n"
            "5. The AI will guide you through the penetration testing process\n"
            "6. You can interact with the AI by entering commands in the console\n\n"
            "For more information, please see the documentation."
        )

    def update_status(self):
        """Periodically update the status bar."""
        # This can be expanded to show more information about the current state
        if self.controller and self.controller.current_phase:
            self.statusBar().showMessage(f"Current phase: {self.controller.current_phase}")

    def closeEvent(self, event):
        """Handle window close event."""
        self.exit_requested = True

        # Properly stop the thread if it's running
        self.cleanup_thread()

        # Clean up the controller
        if self.controller:
            try:
                self.controller.stop_pentest()
                self.controller = None
            except:
                pass

        # Force garbage collection to free resources
        gc.collect()

        # Accept the close event
        event.accept()