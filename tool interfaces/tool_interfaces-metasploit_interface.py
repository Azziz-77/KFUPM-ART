import os
import time
import logging
import subprocess
import tempfile
from typing import Dict, List, Optional, Union
import threading
import queue

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class MetasploitInterface:
    """
    Improved interface to interact with Metasploit through direct msfconsole commands.
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 55553, username: str = "msf", password: str = "password"):
        """
        Initialize the Metasploit interface.
        Note: The host, port, username, and password are kept for API compatibility but not used.
        """
        self.authenticated = True  # Always assume authenticated when using direct console
        self.active_console = None
        self.resource_file_path = None
        self.msfconsole_process = None
        self.active_sessions = {}
        logger.info("Metasploit interface initialized (using direct console commands)")

    def execute_command(self, command: str) -> str:
        """
        Execute a command in Metasploit and return the result.

        Args:
            command: The command to execute

        Returns:
            The command output
        """
        try:
            logger.info(f"Running Metasploit command: {command}")

            # Handle special case for starting msfconsole
            if command.strip() == 'msfconsole':
                return self._start_msfconsole()

            # Check if this is a command to be run in an existing Metasploit session
            if command.startswith("sessions -i"):
                return self._run_session_command(command)

            # Handle Metasploit-specific commands that need to be run inside msfconsole
            msf_internal_commands = [
                'search', 'use', 'show', 'set', 'run', 'exploit', 'sessions',
                'info', 'check', 'back', 'exit', 'options', 'help', 'banner',
                'version'
            ]

            # Commands that should be interpreted as needing msfconsole
            if any(command.strip().startswith(cmd) for cmd in msf_internal_commands) or 'exploit/' in command:
                return self._run_in_msfconsole(command)
            else:
                # Run as a normal shell command
                # Set a reasonable timeout - longer for some commands
                timeout = 60
                if "wget" in command or "curl" in command:
                    timeout = 120  # Longer timeout for download commands

                process = subprocess.run(
                    command,
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=timeout
                )

                # Check for errors
                if process.returncode != 0:
                    logger.error(f"Command failed: {process.stderr}")
                    # If command not found, try to provide helpful guidance
                    if "not found" in process.stderr and any(tool in command for tool in ["wget", "curl", "nmap"]):
                        return f"Error: Command failed. The tool may not be installed.\n{process.stderr}"
                    return f"Error: Command failed with exit code {process.returncode}\n{process.stderr}"

                logger.info(f"Command executed successfully")
                return process.stdout

        except subprocess.TimeoutExpired:
            logger.error(f"Command timed out: {command}")
            return f"Error: Command timed out after {timeout} seconds. For Metasploit operations, consider using individual commands rather than a sequence."
        except Exception as e:
            error_msg = f"Error executing command: {str(e)}"
            logger.error(error_msg)
            return f"Error: {error_msg}"

    def _start_msfconsole(self) -> str:
        """
        Start an msfconsole instance and return a welcome message.
        """
        # Create a non-interactive script to just show banner and version
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.rc') as temp:
            self.resource_file_path = temp.name
            temp.write("banner\n")
            temp.write("version\n")
            temp.write("exit\n")  # Exit after showing version

        try:
            # Run msfconsole with the simple script
            process = subprocess.run(
                ["msfconsole", "-q", "-r", self.resource_file_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=30
            )

            output = process.stdout
            if not output:
                return "Metasploit Framework initialized. Ready for commands."
            return output

        except subprocess.TimeoutExpired:
            return "Metasploit Framework initialized (output timed out). Ready for commands."
        except Exception as e:
            return f"Error starting Metasploit: {str(e)}"
        finally:
            # Clean up the temporary file
            if os.path.exists(self.resource_file_path):
                os.remove(self.resource_file_path)
                self.resource_file_path = None

    def _run_in_msfconsole(self, command: str) -> str:
        """
        Run a command inside msfconsole with improved reliability.

        Args:
            command: The command to run

        Returns:
            The command output
        """
        # Create a temporary resource file
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.rc') as temp:
            self.resource_file_path = temp.name

            # Special handling for 'use' commands - we need to make sure they're properly handled
            if command.startswith("use "):
                module_path = command.replace("use ", "").strip()
                temp.write(f"use {module_path}\n")
                temp.write("info\n")  # Get info about the module
                temp.write("show options\n")  # Show available options
            else:
                # For other commands, just run them directly
                temp.write(f"{command.strip()}\n")

            # Add an echo command to indicate completion
            temp.write("echo ====EXECUTION COMPLETED====\n")
            # Add exit to make sure msfconsole terminates
            temp.write("exit\n")

        try:
            # Determine an appropriate timeout based on the command
            timeout = 60  # Default timeout
            if command.startswith("search"):
                timeout = 90  # Search can take longer
            elif command.startswith("use") or command.startswith("exploit") or command.startswith("run"):
                timeout = 120  # Exploits can take even longer

            # Run msfconsole with the resource file
            process = subprocess.run(
                ["msfconsole", "-q", "-r", self.resource_file_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=timeout
            )

            output = process.stdout

            # Check for completion marker
            if "====EXECUTION COMPLETED====" in output:
                logger.info(f"Metasploit command executed successfully: {command}")
            else:
                logger.warning(f"Metasploit command may not have completed successfully: {command}")

            # Check if any sessions were established
            if "Meterpreter session" in output or "Command shell session" in output:
                self._update_sessions_from_output(output)

            return output

        except subprocess.TimeoutExpired:
            return f"Error: Command '{command}' timed out after {timeout} seconds. Try breaking the command into smaller steps."
        except Exception as e:
            return f"Error executing Metasploit command: {str(e)}"
        finally:
            # Clean up the temporary file
            if os.path.exists(self.resource_file_path):
                os.remove(self.resource_file_path)
                self.resource_file_path = None

    # Enhanced function for tool_interfaces/metasploit_interface.py
    def _run_session_command(self, command: str) -> str:
        """
        Run a command in an existing Metasploit session with direct RPC access.
        This avoids synchronization issues completely.

        Args:
            command: The session command (e.g., 'sessions -i 1 -c "whoami"')

        Returns:
            Command output
        """
        try:
            # Extract session ID and actual command
            import re
            match = re.search(r'sessions\s+-i\s+(\d+)\s+-c\s+[\'"]?(.*?)[\'"]?$', command)

            if not match:
                return f"Error: Invalid session command format. Use: sessions -i SESSION_ID -c \"COMMAND\""

            session_id = match.group(1)
            shell_command = match.group(2).strip()

            # Use the Metasploit RPC client directly - most reliable method
            try:
                from pymetasploit3.msfrpc import MsfRpcClient

                client = MsfRpcClient('password', server='127.0.0.1', port=55553, ssl=False)

                # Verify session exists
                sessions = client.sessions.list
                if session_id not in sessions:
                    return f"Error: Session {session_id} not found"

                # Execute the command directly in the session
                # FIX: Add the required 'end_strs' parameter
                end_markers = ['\n', '$ ', '# ', '> ']
                result = client.sessions.session(session_id).run_with_output(shell_command, end_strs=end_markers)

                # Return the result
                return result.strip() if result else "(Command executed, no output)"

            except Exception as e:
                logger.warning(f"Direct RPC method failed: {str(e)}. Falling back to resource file method.")

                # Fallback to resource file method
                # Create a temporary resource file
                with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.rc') as temp:
                    self.resource_file_path = temp.name
                    # Just run the command and exit immediately
                    temp.write(f"{command.strip()}\n")
                    temp.write("exit\n")

                # Run msfconsole with the resource file
                process = subprocess.run(
                    ["msfconsole", "-q", "-r", self.resource_file_path],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=60
                )

                # Parse the output to extract the command result
                output = process.stdout

                # Try to extract just the command output
                result_lines = []
                capture = False

                for line in output.split('\n'):
                    if f"Running '{shell_command}' on shell session {session_id}" in line:
                        capture = True
                        continue

                    if capture:
                        # Skip msfconsole prompts
                        if line.strip().startswith("msf") and ">" in line:
                            continue
                        result_lines.append(line)

                # Join the captured lines
                return "\n".join(result_lines).strip()

        except Exception as e:
            return f"Error executing session command: {str(e)}"
        finally:
            # Clean up the temporary file
            if hasattr(self, 'resource_file_path') and self.resource_file_path and os.path.exists(
                    self.resource_file_path):
                try:
                    os.remove(self.resource_file_path)
                except:
                    pass
                self.resource_file_path = None

    def _update_sessions_from_output(self, output: str) -> None:
        """
        Update the sessions dictionary based on command output.

        Args:
            output: Command output containing session information
        """
        import re
        session_patterns = [
            r'Meterpreter session (\d+) opened',
            r'Command shell session (\d+) opened'
        ]

        for line in output.split('\n'):
            for pattern in session_patterns:
                match = re.search(pattern, line)
                if match:
                    session_id = match.group(1)
                    session_type = 'meterpreter' if 'Meterpreter' in line else 'shell'
                    self.active_sessions[session_id] = {
                        'type': session_type,
                        'info': line.strip()
                    }
                    logger.info(f"Session {session_id} ({session_type}) recorded")

    def get_sessions(self) -> Dict:
        """
        Get all active sessions.

        Returns:
            Dictionary of active sessions
        """
        try:
            # First update our session tracking with the latest from Metasploit
            output = self._run_in_msfconsole("sessions -l")

            # Parse the output to extract session information
            import re
            sessions = {}
            in_sessions_list = False

            for line in output.split('\n'):
                # Check if we've reached the sessions list section
                if line.strip().startswith('Id') and 'Type' in line:
                    in_sessions_list = True
                    continue

                if in_sessions_list and line.strip():
                    # Try to extract session info using regex
                    match = re.match(r'\s*(\d+)\s+(\S+)\s+(.+)', line)
                    if match:
                        session_id = match.group(1)
                        session_type = match.group(2)
                        info = match.group(3).strip()
                        sessions[session_id] = {
                            'type': session_type,
                            'info': info
                        }

            # Update our tracking
            if sessions:
                self.active_sessions = sessions

            return self.active_sessions

        except Exception as e:
            logger.error(f"Error getting sessions: {str(e)}")
            return self.active_sessions  # Return what we already know

    def upload_file_to_session(self, session_id: int, local_file: str, remote_file: str) -> bool:
        """
        Upload a file to a session.

        Args:
            session_id: The session ID
            local_file: The local file path
            remote_file: The remote file path

        Returns:
            True if successful, False otherwise
        """
        try:
            command = f"sessions -i {session_id} -c 'upload {local_file} {remote_file}'"
            result = self._run_in_msfconsole(command)
            return "uploaded" in result.lower()
        except Exception as e:
            logger.error(f"Error uploading file to session: {str(e)}")
            return False

    def execute_shell_command(self, session_id: int, command: str) -> str:
        """
        Execute a shell command in a session.

        Args:
            session_id: The session ID
            command: The command to execute

        Returns:
            The command output
        """
        try:
            msf_command = f"sessions -i {session_id} -c '{command}'"
            return self._run_in_msfconsole(msf_command)
        except Exception as e:
            logger.error(f"Error executing shell command in session: {str(e)}")
            return f"Error: {str(e)}"

    def cleanup(self):
        """Clean up resources."""
        # Close any open sessions to be safe
        try:
            self._run_in_msfconsole("sessions -K")
            self.active_sessions = {}
        except:
            pass

        # Clean up resource file if it exists
        if self.resource_file_path and os.path.exists(self.resource_file_path):
            try:
                os.remove(self.resource_file_path)
            except:
                pass
            self.resource_file_path = None

    def execute_with_timeout(self, command: str, timeout: int = 60) -> str:
        """
        Execute a command with a timeout.

        Args:
            command: The command to execute
            timeout: Timeout in seconds

        Returns:
            Command output
        """
        result_queue = queue.Queue()

        def target():
            try:
                result = self.execute_command(command)
                result_queue.put(result)
            except Exception as e:
                result_queue.put(f"Error: {str(e)}")

        thread = threading.Thread(target=target)
        thread.daemon = True
        thread.start()

        try:
            return result_queue.get(timeout=timeout)
        except queue.Empty:
            return f"Error: Command timed out after {timeout} seconds"