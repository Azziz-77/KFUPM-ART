from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTextEdit,
    QLineEdit, QPushButton, QLabel, QTextBrowser,
    QScrollBar, QSizePolicy
)
from PyQt6.QtCore import Qt, pyqtSignal, QTimer
from PyQt6.QtGui import QTextCursor, QColor, QFont, QTextCharFormat, QBrush


class ConsoleWidget(QWidget):
    """
    A widget that displays console output and allows user input with improved
    formatting, readability, and user experience.
    """

    # Define a signal for when the user submits a command
    command_submitted = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.init_ui()
        self.last_output_type = None
        self.auto_scroll_timer = QTimer(self)
        self.auto_scroll_timer.timeout.connect(self.ensure_visible)
        self.auto_scroll_timer.setInterval(100)  # 100ms delay for smooth scrolling

    def init_ui(self):
        """Initialize the UI components."""
        # Main layout
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        layout.setContentsMargins(10, 10, 10, 10)

        # Output display area with monospace font
        self.output_display = QTextBrowser()  # Changed to QTextBrowser for better formatting support
        self.output_display.setReadOnly(True)
        font = QFont("Consolas", 10)  # Modern monospace font
        self.output_display.setFont(font)
        self.output_display.setOpenExternalLinks(True)  # Allow hyperlinks to open

        # Set a stylish background color
        self.output_display.setStyleSheet("""
            QTextBrowser {
                background-color: #1E1E1E;
                color: #D4D4D4;
                border: 1px solid #3E3E3E;
                border-radius: 4px;
                padding: 8px;
            }
        """)

        # Make the output area expand to fill available space
        self.output_display.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)

        layout.addWidget(self.output_display)

        # Input area with prompt
        input_layout = QHBoxLayout()
        input_layout.setSpacing(5)

        # Command prompt label with stylish appearance
        prompt_label = QLabel("> ")
        prompt_label.setStyleSheet("color: #569CD6; font-weight: bold;")
        prompt_label.setFont(font)
        input_layout.addWidget(prompt_label)

        # Command input field with styling
        self.command_input = QLineEdit()
        self.command_input.setFont(font)
        self.command_input.setStyleSheet("""
            QLineEdit {
                background-color: #252526;
                color: #D4D4D4;
                border: 1px solid #3E3E3E;
                border-radius: 4px;
                padding: 5px;
            }
        """)
        self.command_input.returnPressed.connect(self.submit_command)
        input_layout.addWidget(self.command_input)

        # Submit button
        submit_button = QPushButton("Submit")
        submit_button.setStyleSheet("""
            QPushButton {
                background-color: #0E639C;
                color: white;
                border: none;
                border-radius: 4px;
                padding: 5px 15px;
            }
            QPushButton:hover {
                background-color: #1177BB;
            }
            QPushButton:pressed {
                background-color: #0D5A8E;
            }
        """)
        submit_button.clicked.connect(self.submit_command)
        input_layout.addWidget(submit_button)

        layout.addLayout(input_layout)

    def submit_command(self):
        """Handle command submission."""
        command = self.command_input.text().strip()
        if command:
            # Display the command with user style
            self.append_text(f"$ {command}", "user")

            # Emit the signal with the command
            self.command_submitted.emit(command)

            # Clear the input field
            self.command_input.clear()

    def append_text(self, text, source="system"):
        """
        Append text to the output display with appropriate formatting.

        Args:
            text: The text to append
            source: The source of the text ('system', 'user', 'ai', 'error')
        """
        # Define colors for different sources
        colors = {
            "system": QColor(180, 180, 180),  # Light gray
            "user": QColor(97, 175, 239),  # Blue
            "ai": QColor(152, 195, 121),  # Green
            "error": QColor(224, 108, 117),  # Red
            "success": QColor(152, 195, 121),  # Green
            "warning": QColor(229, 192, 123)  # Yellow
        }

        # Define icons for each source for better visual distinction
        icons = {
            "system": "🖥️ ",
            "user": "👤 ",
            "ai": "🤖 ",
            "error": "❌ ",
            "success": "✅ ",
            "warning": "⚠️ "
        }

        # Insert section separator if the source type changes
        if self.last_output_type is not None and self.last_output_type != source:
            self.insert_separator()

        self.last_output_type = source

        # Get the current cursor and text color
        cursor = self.output_display.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        self.output_display.setTextCursor(cursor)

        # Set color based on source
        color = colors.get(source, QColor(255, 255, 255))  # Default to white

        # Create format with the appropriate color
        format = QTextCharFormat()
        format.setForeground(QBrush(color))

        # Add bold formatting for headers
        if source in ["system", "error", "success", "warning"]:
            format.setFontWeight(QFont.Weight.Bold)

        cursor.setCharFormat(format)

        # Insert the appropriate icon
        icon = icons.get(source, "")
        cursor.insertText(f"{icon}")

        # Insert the text with proper line breaks and formatting
        formatted_text = self.format_text(text, source)
        cursor.insertText(formatted_text)

        # Add an extra line at the end for readability
        cursor.insertText("\n")

        # Ensure the cursor is visible by scrolling to it
        self.output_display.ensureCursorVisible()
        self.auto_scroll_timer.start()

    def format_text(self, text, source):
        """
        Format the text for better readability based on source type.

        Args:
            text: The text to format
            source: The source type

        Returns:
            Formatted text
        """
        # For AI responses, handle code blocks better
        if source == "ai":
            # If the AI removed its own prefix, add it back
            if not text.startswith("🤖"):
                text = text

            # Better handling of code blocks
            lines = text.split('\n')
            formatted_lines = []
            in_code_block = False

            for line in lines:
                if line.strip().startswith('```') or line.strip().endswith('```'):
                    in_code_block = not in_code_block
                    # Add some visual distinction for code block markers
                    formatted_lines.append("─" * 50 if in_code_block else "─" * 50)
                    continue

                if in_code_block:
                    # Format code with slight indentation for better readability
                    formatted_lines.append("    " + line)
                else:
                    formatted_lines.append(line)

            return '\n'.join(formatted_lines)

        # For system results, improve readability of command outputs
        elif source == "system" and text.startswith("Result:"):
            lines = text.split('\n')
            if len(lines) > 1:
                # Format command results with clearer separation
                return lines[0] + "\n" + "─" * 50 + "\n" + '\n'.join(lines[1:])

        # Return the original text for other sources
        return text

    def insert_separator(self):
        """Insert a visual separator between different message types for better readability."""
        cursor = self.output_display.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)

        format = QTextCharFormat()
        format.setForeground(QBrush(QColor(100, 100, 100)))  # Dark gray color
        cursor.setCharFormat(format)

        cursor.insertText("\n" + "─" * 80 + "\n\n")

    def ensure_visible(self):
        """Ensure the latest content is visible by scrolling to the bottom."""
        scrollbar = self.output_display.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())
        self.auto_scroll_timer.stop()

    def clear_console(self):
        """Clear the console output."""
        self.output_display.clear()
        self.last_output_type = None