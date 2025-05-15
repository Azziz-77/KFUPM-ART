import os
import json
import time
import logging
import requests
from typing import Dict, List, Optional, Union

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class CalderaInterface:
    """
    Interface to interact with CALDERA through its REST API.
    """

    def __init__(self, api_url: str = "http://localhost:8888", api_key: str = "ADMIN123"):
        """
        Initialize the CALDERA interface.

        Args:
            api_url: The URL of the CALDERA API
            api_key: The API key for authentication
        """
        self.api_url = api_url
        self.api_key = api_key
        self.headers = {
            'KEY': api_key,
            'Content-Type': 'application/json'
        }
        self.operation_id = None

        # Test connection
        self.test_connection()

    def test_connection(self) -> bool:
        """
        Test the connection to the CALDERA API.

        Returns:
            True if successful, False otherwise
        """
        try:
            response = requests.get(
                f"{self.api_url}/api/v2/abilities",
                headers=self.headers,
                timeout=10
            )

            if response.status_code == 200:
                logger.info("Successfully connected to CALDERA API")
                return True
            else:
                logger.error(f"Failed to connect to CALDERA API: {response.status_code}")
                return False

        except Exception as e:
            logger.error(f"Error connecting to CALDERA API: {str(e)}")
            return False

    def execute_command(self, command: str) -> str:
        """
        Execute a CALDERA command and return the result.
        This is a high-level wrapper that handles different CALDERA operations.

        Args:
            command: The command to execute. Format: operation:parameters

        Returns:
            The command output
        """
        try:
            # Parse the command
            parts = command.strip().split(':', 1)
            operation = parts[0].strip().lower()

            if len(parts) > 1:
                parameters = parts[1].strip()
            else:
                parameters = ""

            # Handle different operations
            if operation == "list_abilities":
                return self._format_output(self.get_abilities())

            elif operation == "list_agents":
                return self._format_output(self.get_agents())

            elif operation == "create_operation":
                # Expected format: create_operation:adversary_id,group_id,name
                try:
                    op_params = parameters.split(',')
                    adversary_id = op_params[0]
                    group_id = op_params[1] if len(op_params) > 1 else "red"
                    name = op_params[2] if len(op_params) > 2 else f"Operation-{time.time()}"

                    result = self.create_operation(adversary_id, group_id, name)
                    self.operation_id = result.get('id')
                    return self._format_output(result)
                except Exception as e:
                    return f"Error creating operation: {str(e)}"

            elif operation == "get_operation_status":
                # Expected format: get_operation_status:operation_id
                op_id = parameters or self.operation_id
                if not op_id:
                    return "No operation ID specified or active"
                return self._format_output(self.get_operation_status(op_id))

            elif operation == "get_operation_results":
                # Expected format: get_operation_results:operation_id
                op_id = parameters or self.operation_id
                if not op_id:
                    return "No operation ID specified or active"
                return self._format_output(self.get_operation_results(op_id))

            elif operation == "create_adversary":
                # Expected format: create_adversary:name,description,ability_id1,ability_id2,...
                try:
                    adv_params = parameters.split(',')
                    name = adv_params[0]
                    description = adv_params[1]
                    abilities = adv_params[2:] if len(adv_params) > 2 else []

                    return self._format_output(self.create_adversary(name, description, abilities))
                except Exception as e:
                    return f"Error creating adversary: {str(e)}"

            else:
                return f"Unknown CALDERA operation: {operation}"

        except Exception as e:
            error_msg = f"Error executing CALDERA command: {str(e)}"
            logger.error(error_msg)
            return f"Error: {error_msg}"

    def _format_output(self, data: Union[Dict, List, str]) -> str:
        """
        Format the output data to a readable string.

        Args:
            data: The data to format

        Returns:
            Formatted string
        """
        if isinstance(data, (dict, list)):
            return json.dumps(data, indent=2)
        return str(data)

    def get_abilities(self, tactic: Optional[str] = None) -> List[Dict]:
        """
        Get available abilities from CALDERA.

        Args:
            tactic: Optional filter by MITRE ATT&CK tactic (e.g. 'credential-access')

        Returns:
            List of ability dictionaries
        """
        try:
            url = f"{self.api_url}/api/v2/abilities"
            if tactic:
                url += f"?tactic={tactic}"

            response = requests.get(url, headers=self.headers, timeout=30)

            if response.status_code == 200:
                abilities = response.json()
                logger.info(f"Retrieved {len(abilities)} abilities" +
                            (f" for tactic {tactic}" if tactic else ""))
                return abilities
            else:
                logger.error(f"Failed to get abilities: {response.status_code} - {response.text}")
                return []

        except Exception as e:
            logger.error(f"Exception getting abilities: {str(e)}")
            return []

    def get_agents(self) -> List[Dict]:
        """
        Get list of available agents.

        Returns:
            List of agent dictionaries
        """
        try:
            response = requests.get(
                f"{self.api_url}/api/v2/agents",
                headers=self.headers,
                timeout=30
            )

            if response.status_code == 200:
                agents = response.json()
                logger.info(f"Retrieved {len(agents)} agents")
                return agents
            else:
                logger.error(f"Failed to get agents: {response.status_code} - {response.text}")
                return []

        except Exception as e:
            logger.error(f"Exception getting agents: {str(e)}")
            return []

    def create_adversary(self, name: str, description: str, abilities: List[str]) -> Dict:
        """
        Create a custom adversary profile in CALDERA.

        Args:
            name: Name for the adversary profile
            description: Description of the adversary profile
            abilities: List of ability IDs to include

        Returns:
            Created adversary profile
        """
        try:
            # If empty abilities list, add some default ones
            if not abilities:
                logger.warning("No abilities provided, adding some defaults")
                # Get some default abilities from different tactics
                credential_access = self.get_abilities("credential-access")
                discovery = self.get_abilities("discovery")
                execution = self.get_abilities("execution")

                for tactic_abilities in [credential_access, discovery, execution]:
                    if tactic_abilities and len(tactic_abilities) > 0:
                        abilities.append(tactic_abilities[0].get('ability_id'))

            data = {
                "name": name,
                "description": description,
                "atomic_ordering": abilities
            }

            response = requests.post(
                f"{self.api_url}/api/v2/adversaries",
                headers=self.headers,
                json=data,
                timeout=30
            )

            if response.status_code == 200:
                adversary = response.json()
                logger.info(f"Created adversary profile: {name}")
                return adversary
            else:
                logger.error(f"Failed to create adversary: {response.status_code} - {response.text}")
                return {"error": f"Status code: {response.status_code}", "message": response.text}

        except Exception as e:
            logger.error(f"Exception creating adversary: {str(e)}")
            return {"error": str(e)}

    def create_operation(self, adversary_id: str, group_id: str = "red", name: Optional[str] = None) -> Dict:
        """
        Create and start a new operation.

        Args:
            adversary_id: ID of the adversary profile to use
            group_id: ID of the group to target
            name: Operation name (optional)

        Returns:
            Created operation details
        """
        try:
            operation_name = name or f"AI-Generated-Op-{int(time.time())}"

            data = {
                "name": operation_name,
                "adversary_id": adversary_id,
                "group": group_id,
                "state": "running"
            }

            logger.info(f"Creating operation with data: {json.dumps(data)}")

            response = requests.post(
                f"{self.api_url}/api/v2/operations",
                headers=self.headers,
                json=data,
                timeout=30
            )

            if response.status_code == 200:
                operation = response.json()
                self.operation_id = operation.get('id')
                logger.info(f"Created and started operation: {operation_name} (ID: {self.operation_id})")
                return operation
            else:
                logger.error(f"Failed to create operation: {response.status_code} - {response.text}")
                return {"error": f"Status code: {response.status_code}", "message": response.text}

        except requests.exceptions.Timeout:
            logger.error("Timeout while creating operation")
            return {"error": "Timeout while creating operation"}
        except Exception as e:
            logger.error(f"Exception creating operation: {str(e)}")
            return {"error": str(e)}

    def get_operation_status(self, operation_id: Optional[str] = None) -> Dict:
        """
        Get the status of an operation.

        Args:
            operation_id: ID of the operation, defaults to current operation

        Returns:
            Operation status dictionary
        """
        try:
            op_id = operation_id or self.operation_id
            if not op_id:
                return {"error": "No operation ID specified or active"}

            response = requests.get(
                f"{self.api_url}/api/v2/operations/{op_id}",
                headers=self.headers,
                timeout=30
            )

            if response.status_code == 200:
                return response.json()
            else:
                logger.error(f"Failed to get operation status: {response.status_code} - {response.text}")
                return {"state": "unknown", "error": response.text}

        except Exception as e:
            logger.error(f"Exception getting operation status: {str(e)}")
            return {"state": "unknown", "error": str(e)}

    def get_operation_results(self, operation_id: Optional[str] = None) -> List[Dict]:
        """
        Get the results of an operation.

        Args:
            operation_id: ID of the operation, defaults to current operation

        Returns:
            List of operation result facts
        """
        try:
            op_id = operation_id or self.operation_id
            if not op_id:
                return [{"error": "No operation ID specified or active"}]

            # Try the v2 endpoint first
            response = requests.get(
                f"{self.api_url}/api/v2/operations/{op_id}/result",
                headers=self.headers,
                timeout=30
            )

            # If 404, try alternative endpoints
            if response.status_code == 404:
                # Try the facts endpoint
                response = requests.get(
                    f"{self.api_url}/api/v2/operations/{op_id}/facts",
                    headers=self.headers,
                    timeout=30
                )

            if response.status_code == 404:
                # Try without /result
                response = requests.get(
                    f"{self.api_url}/api/v2/operations/{op_id}",
                    headers=self.headers,
                    timeout=30
                )

            if response.status_code == 200:
                results = response.json()
                logger.info(f"Retrieved results for operation {op_id}")
                return results
            else:
                logger.error(f"Failed to get operation results: {response.status_code} - {response.text}")
                return [{"error": f"Failed to get results: {response.status_code}"}]

        except Exception as e:
            logger.error(f"Exception getting operation results: {str(e)}")
            return [{"error": str(e)}]

    def finish_operation(self, operation_id: Optional[str] = None) -> Dict:
        """
        Finish an operation and get its final status.

        Args:
            operation_id: ID of the operation to finish, defaults to current operation

        Returns:
            Final operation status
        """
        try:
            op_id = operation_id or self.operation_id
            if not op_id:
                return {"error": "No operation ID specified or active"}

            # Update operation state to finished
            data = {"state": "finished"}
            response = requests.patch(
                f"{self.api_url}/api/v2/operations/{op_id}",
                headers=self.headers,
                json=data,
                timeout=30
            )

            if response.status_code == 200:
                logger.info(f"Operation {op_id} manually finished")
                return response.json()
            else:
                logger.error(f"Failed to finish operation: {response.status_code} - {response.text}")
                return {"error": f"Failed to finish operation: {response.status_code}"}

        except Exception as e:
            logger.error(f"Exception finishing operation: {str(e)}")
            return {"error": str(e)}

    def cleanup(self):
        """Clean up resources and finish any active operations."""
        try:
            if self.operation_id:
                self.finish_operation(self.operation_id)
                logger.info(f"Cleaned up operation: {self.operation_id}")
        except Exception as e:
            logger.error(f"Error cleaning up CALDERA resources: {str(e)}")