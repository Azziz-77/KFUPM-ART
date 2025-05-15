import os
import configparser
import logging
from typing import Dict, Any, Optional

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class ConfigManager:
    """
    Configuration manager for AI-guided Penetration Testing Tool.
    Handles reading, writing, and validating configuration.
    """

    def __init__(self, config_file: str = "./config/config.ini"):
        """
        Initialize the Configuration Manager.

        Args:
            config_file: Path to the configuration file
        """
        self.config_file = config_file
        self.config = configparser.ConfigParser()

        # Initialize with default values
        self._set_defaults()

        # Load configuration from file if it exists
        if os.path.exists(config_file):
            try:
                self.config.read(config_file)
                logger.info(f"Configuration loaded from {config_file}")
            except Exception as e:
                logger.error(f"Error loading configuration: {str(e)}")
                # Keep defaults if config file can't be loaded
        else:
            logger.warning(f"Configuration file {config_file} not found, using defaults")
            self._create_default_config()

    def _set_defaults(self):
        """Set default configuration values."""
        self.config["DEFAULT"] = {
            "workspace_dir": "./workspace",
            "log_level": "INFO"
        }

        self.config["METASPLOIT"] = {
            "host": "127.0.0.1",
            "port": "55552",
            "username": "msf",
            "password": "password"
        }

        self.config["CALDERA"] = {
            "url": "http://localhost:8888",
            "api_key": "ADMIN123"
        }

        self.config["API"] = {
            "openai_api_key": ""
        }

    def _create_default_config(self):
        """Create a default configuration file."""
        try:
            # Ensure directory exists
            os.makedirs(os.path.dirname(self.config_file), exist_ok=True)

            # Write configuration to file
            with open(self.config_file, 'w') as f:
                self.config.write(f)

            logger.info(f"Default configuration created at {self.config_file}")
        except Exception as e:
            logger.error(f"Error creating default configuration: {str(e)}")

    def get_section(self, section: str) -> Dict[str, str]:
        """
        Get all values for a section.

        Args:
            section: Section name

        Returns:
            Dictionary with section values
        """
        if section in self.config:
            return dict(self.config[section])
        else:
            logger.warning(f"Section {section} not found in configuration")
            return {}

    def get_value(self, section: str, key: str, default: Any = None) -> Any:
        """
        Get a specific configuration value.

        Args:
            section: Section name
            key: Configuration key
            default: Default value if not found

        Returns:
            Configuration value or default
        """
        try:
            if section in self.config and key in self.config[section]:
                return self.config[section][key]
            else:
                logger.warning(f"Value for {section}.{key} not found, using default: {default}")
                return default
        except Exception as e:
            logger.error(f"Error getting configuration value {section}.{key}: {str(e)}")
            return default

    def set_value(self, section: str, key: str, value: str) -> bool:
        """
        Set a configuration value.

        Args:
            section: Section name
            key: Configuration key
            value: Value to set

        Returns:
            True if successful, False otherwise
        """
        try:
            if section not in self.config:
                self.config[section] = {}

            self.config[section][key] = value

            # Write changes to file
            with open(self.config_file, 'w') as f:
                self.config.write(f)

            logger.info(f"Configuration value {section}.{key} set to {value}")
            return True
        except Exception as e:
            logger.error(f"Error setting configuration value {section}.{key}: {str(e)}")
            return False

    def get_workspace_dir(self) -> str:
        """
        Get the workspace directory.

        Returns:
            Workspace directory path
        """
        workspace_dir = self.get_value("DEFAULT", "workspace_dir", "./workspace")

        # Ensure the directory exists
        os.makedirs(workspace_dir, exist_ok=True)

        return workspace_dir

    def get_metasploit_config(self) -> Dict[str, str]:
        """
        Get Metasploit configuration.

        Returns:
            Dictionary with Metasploit configuration
        """
        return self.get_section("METASPLOIT")

    def get_caldera_config(self) -> Dict[str, str]:
        """
        Get CALDERA configuration.

        Returns:
            Dictionary with CALDERA configuration
        """
        return self.get_section("CALDERA")

    def get_api_key(self) -> Optional[str]:
        """
        Get OpenAI API key.

        Returns:
            API key or None if not set
        """
        api_key = self.get_value("API", "openai_api_key", "")
        if not api_key:
            logger.warning("OpenAI API key not set in configuration")
            return None
        return api_key

    def set_api_key(self, api_key: str) -> bool:
        """
        Set OpenAI API key.

        Args:
            api_key: API key to set

        Returns:
            True if successful, False otherwise
        """
        return self.set_value("API", "openai_api_key", api_key)


# Singleton instance
_config_manager = None


def get_config_manager(config_file: str = "./config/config.ini") -> ConfigManager:
    """
    Get the singleton ConfigManager instance.

    Args:
        config_file: Path to the configuration file

    Returns:
        ConfigManager instance
    """
    global _config_manager
    if _config_manager is None:
        _config_manager = ConfigManager(config_file)
    return _config_manager