"""Protocol implemented by built-in and third-party scanners."""
from typing import Protocol
from ..models import Context, PluginResult

class ScannerPlugin(Protocol):
    name: str

    def matches(self, package_name: str) -> bool:
        """Whether this scanner understands a declared package/image identifier."""
        ...

    def detect(self, context: Context) -> bool:
        """Whether repository configuration provides non-package evidence."""
        ...

    def scan(self, context: Context, stop_on_finding: bool = False) -> PluginResult:
        ...
