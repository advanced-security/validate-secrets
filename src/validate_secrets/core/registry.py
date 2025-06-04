"""Plugin registry and auto-discovery system."""

import importlib
import inspect
import pkgutil
import logging
from pathlib import Path
from typing import Dict, Type, List, Any

from .exceptions import ValidatorError

LOG = logging.getLogger(__name__)


class ValidatorRegistry:
    """Registry for dynamically loaded validators."""

    def __init__(self):
        self._validators: Dict[str, Type[Any]] = {}
        self._loaded = False

    def load_validators(self) -> Dict[str, Type]:
        """Dynamically load all validators from the validators directory."""
        if self._loaded:
            return self._validators

        # Import Checker here to avoid import conflicts
        from .base import Checker

        self._validators.clear()

        # Get the validators directory path
        # TODO: Make this configurable if needed
        validators_path = Path(__file__).parent.parent / "validators"

        if not validators_path.exists():
            LOG.warning(f"Validators directory not found: {validators_path}")
            return self._validators

        LOG.debug(f"Scanning for validators in: {validators_path}")

        # Scan for validator modules
        for module_info in pkgutil.iter_modules([str(validators_path)]):
            if module_info.name.startswith("_"):
                continue

            try:
                # Import the module - try both absolute and relative paths
                try:
                    module_name = f"validate_secrets.validators.{module_info.name}"
                    module = importlib.import_module(module_name)
                except ImportError:
                    # Try with the current package structure
                    module_name = f"src.validate_secrets.validators.{module_info.name}"
                    module = importlib.import_module(module_name)

                # Find Checker subclasses in the module
                found_validator = False
                for name, obj in inspect.getmembers(module, inspect.isclass):
                    if (
                        issubclass(obj, Checker)
                        and obj.__name__ != "Checker"
                        and obj.__module__ == module.__name__
                    ):
                        # Use the validator's name attribute or fall back to module name
                        validator_name = getattr(obj, "name", None) or module_info.name

                        if validator_name in self._validators:
                            LOG.warning(
                                f"Duplicate validator name '{validator_name}' found in {module_info.name}"
                            )
                            continue

                        self._validators[validator_name] = obj
                        LOG.debug(f"Registered validator: {validator_name} -> {obj.__name__}")
                        found_validator = True
                        break  # Only one validator per module

                if not found_validator:
                    LOG.warning(f"No Checker subclass found in module: {module_info.name}")

            except Exception as e:
                LOG.error(f"Failed to load validator module {module_info.name}: {e}")
                continue

        self._loaded = True
        LOG.info(f"Loaded {len(self._validators)} validators: {list(self._validators.keys())}")
        return self._validators

    def get_validator(self, name: str) -> Type[Any]:
        """Get a validator by name."""
        if not self._loaded:
            self.load_validators()

        if name not in self._validators:
            available = list(self._validators.keys())
            raise ValidatorError(f"Unknown validator '{name}'. Available: {available}")

        return self._validators[name]

    def list_validators(self) -> List[str]:
        """List all available validator names."""
        if not self._loaded:
            self.load_validators()
        return list(self._validators.keys())

    def get_validator_info(self) -> Dict[str, Dict]:
        """Get detailed information about all validators."""
        if not self._loaded:
            self.load_validators()

        info = {}
        for name, validator_class in self._validators.items():
            # Create a temporary instance to get metadata
            try:
                temp_instance = validator_class()
                info[name] = temp_instance.get_metadata()
            except Exception as e:
                info[name] = {"name": name, "class": validator_class.__name__, "error": str(e)}
        return info


# Global registry instance
_registry = ValidatorRegistry()


def get_validators() -> Dict[str, Type[Any]]:
    """Get all loaded validators."""
    return _registry.load_validators()


def get_validator(name: str) -> Type[Any]:
    """Get a specific validator by name."""
    return _registry.get_validator(name)


def list_validators() -> List[str]:
    """List all available validator names."""
    return _registry.list_validators()


def get_validator_info() -> Dict[str, Dict]:
    """Get detailed information about all validators."""
    return _registry.get_validator_info()
