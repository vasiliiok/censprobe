"""
Censprobe Core — shared measurement library.
"""

# `__version__` is set BEFORE the submodule imports so that runner.py /
# baseline_builder.py (in sibling packages) can `from censprobe_core import
# __version__` without hitting a partially-loaded module during the import
# graph traversal.
__version__ = "0.1.0"

from censprobe_core.models import (
    Verdict,
    BlockingMethod,
    TestResult,
    BaselineData,
    ReportMeta,
    ServerMeta,
    ListenerReport,
    ProtocolResult,
)
from censprobe_core.runner import ProbeRunner
from censprobe_core.baseline import BaselineComparator

__all__ = [
    "Verdict",
    "BlockingMethod",
    "TestResult",
    "BaselineData",
    "ReportMeta",
    "ServerMeta",
    "ListenerReport",
    "ProtocolResult",
    "ProbeRunner",
    "BaselineComparator",
]
