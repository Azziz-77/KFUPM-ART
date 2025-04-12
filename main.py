#!/usr/bin/env python3

import sys
import os
from PyQt6.QtWidgets import QApplication, QSplashScreen
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QPixmap

# Import the main GUI class
from gui_main import PenetrationTestingGUI


def main():
    """Main application entry point"""
    # Create application
    app = QApplication(sys.argv)
    app.setStyle("Fusion")

    # Create a very simple splash screen without relying on an image file
    splash_pixmap = QPixmap(500, 300)
    splash_pixmap.fill(Qt.GlobalColor.black)
    #splash_pixmap = QPixmap('splash.png')




    # Show splash screen
    splash = QSplashScreen(splash_pixmap)
    splash.setWindowFlags(Qt.WindowType.WindowStaysOnTopHint | Qt.WindowType.SplashScreen)
    splash.show()
    splash.showMessage("Loading Advanced Penetration Testing Suite...",
                       Qt.AlignmentFlag.AlignBottom | Qt.AlignmentFlag.AlignCenter,
                       Qt.GlobalColor.white)
    app.processEvents()

    # Create main window after slight delay
    def show_main_window():
        # Create main window
        window = PenetrationTestingGUI()

        # Close splash and show main window
        splash.finish(window)
        window.show()

    # Use timer for splash screen effect
    QTimer.singleShot(1000, show_main_window)

    # Execute applicationS
    sys.exit(app.exec())


if __name__ == "__main__":
    # Create application
    app = QApplication(sys.argv)
    app.setStyle("Fusion")

    # Create main window
    window = PenetrationTestingGUI()
    window.show()


    # This prevents the program from terminating
    def keep_alive():
        import time
        while True:
            # Keep the process alive by doing nothing
            time.sleep(5)
            #print("Application still running...")


    # Start the keep-alive thread
    import threading

    t = threading.Thread(target=keep_alive, daemon=True)
    t.start()

    # Start the application event loop
    sys.exit(app.exec())