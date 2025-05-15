#!/usr/bin/env python3

import sys
import os
import logging
from PyQt6.QtWidgets import QApplication, QSplashScreen, QMessageBox
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QPixmap

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("app.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Import the config manager
try:
    from utils.config_manager import get_config_manager

    config_manager = get_config_manager()
    logger.info("Configuration manager loaded successfully")
except Exception as e:
    logger.error(f"Error loading configuration manager: {str(e)}")
    config_manager = None

# Import the main GUI class
try:
    from gui import AIPentestGUI

    logger.info("GUI module loaded successfully")
except Exception as e:
    logger.error(f"Error loading GUI module: {str(e)}")


    # Define a function to show error and exit
    def show_error_and_exit(message):
        app = QApplication(sys.argv)
        QMessageBox.critical(None, "Error", message)
        sys.exit(1)


def check_dependencies():
    """Check if all required dependencies are installed."""
    try:
        # Check for required tools
        required_tools = ["nmap", "searchsploit", "msfconsole"]
        missing_tools = []

        for tool in required_tools:
            if os.system(f"which {tool} > /dev/null 2>&1") != 0:
                missing_tools.append(tool)

        if missing_tools:
            missing_tools_str = ", ".join(missing_tools)
            logger.error(f"Missing required tools: {missing_tools_str}")
            show_error_and_exit(f"Missing required tools: {missing_tools_str}\n\n"
                                f"Please run the setup.sh script to install all dependencies.")
            return False

        # Check for Python dependencies
        try:
            import openai
            from PyQt6.QtWidgets import QApplication
        except ImportError as e:
            logger.error(f"Missing Python dependency: {str(e)}")
            show_error_and_exit(f"Missing Python dependency: {str(e)}\n\n"
                                f"Please run: pip install PyQt6 openai requests")
            return False

        logger.info("All dependencies check passed")
        return True

    except Exception as e:
        logger.error(f"Error checking dependencies: {str(e)}")
        return False


def main():
    """Main application entry point"""
    try:
        # Check dependencies
        if not check_dependencies():
            return

        # Create application
        app = QApplication(sys.argv)
        app.setStyle("Fusion")

        # Set application information
        app.setApplicationName("AI-Guided Penetration Testing")
        app.setApplicationVersion("1.0.0")
        app.setOrganizationName("Security Research")

        # Create a splash screen
        splash_path = "ART.png"
        if os.path.exists(splash_path):
            splash_pixmap = QPixmap(splash_path).scaled(500, 500, Qt.AspectRatioMode.KeepAspectRatio)
        else:
            # Create a simple splash screen if image not found
            splash_pixmap = QPixmap(500, 300)
            splash_pixmap.fill(Qt.GlobalColor.black)

        # Show splash screen
        splash = QSplashScreen(splash_pixmap)
        splash.setWindowFlags(Qt.WindowType.WindowStaysOnTopHint | Qt.WindowType.SplashScreen)
        splash.show()
        splash.showMessage("Loading AI-Guided Penetration Testing Suite...",
                           Qt.AlignmentFlag.AlignBottom | Qt.AlignmentFlag.AlignCenter,
                           Qt.GlobalColor.white)
        app.processEvents()

        # Ensure workspace directory exists
        workspace_dir = config_manager.get_workspace_dir()
        logger.info(f"Using workspace directory: {workspace_dir}")

        # Function to create and show main window
        def show_main_window():
            try:
                # Create main window
                window = AIPentestGUI()

                # Configure window from settings if config manager is available
                if config_manager:
                    # Set API key from config if available
                    api_key = config_manager.get_api_key()
                    if api_key:
                        window.api_key = api_key
                        window.api_key_input.setText(api_key)

                    # Set workspace directory
                    window.workspace_input.setText(workspace_dir)

                    # Set Metasploit configuration
                    msf_config = config_manager.get_metasploit_config()
                    if msf_config:
                        window.msf_host.setText(msf_config.get("host", "127.0.0.1"))
                        window.msf_port.setText(msf_config.get("port", "55552"))

                    # Set CALDERA configuration
                    caldera_config = config_manager.get_caldera_config()
                    if caldera_config:
                        window.caldera_url.setText(caldera_config.get("url", "http://localhost:8888"))
                        window.caldera_key.setText(caldera_config.get("api_key", "ADMIN123"))

                # Close splash and show main window
                splash.finish(window)
                window.show()

                logger.info("Main window created and shown")
            except Exception as e:
                logger.error(f"Error creating main window: {str(e)}")
                QMessageBox.critical(None, "Error", f"Error creating main window: {str(e)}")
                sys.exit(1)

        # Use timer for splash screen effect
        QTimer.singleShot(1500, show_main_window)

        # Execute application
        sys.exit(app.exec())

    except Exception as e:
        logger.error(f"Critical error in main function: {str(e)}")
        QMessageBox.critical(None, "Critical Error", f"An unexpected error occurred: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()