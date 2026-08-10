"""Public package for the AstrBot Safe Backup cold-backup engine."""

from .engine import (
    BackupError,
    Result,
    configuration_fingerprint,
    main,
    parse_args,
    run,
    source_fingerprints,
    verify_archive,
)
from .setup import (
    SetupConfig,
    InitializationLedger,
    build_setup_config,
    initialize_destination,
    rollback_initialized_destination,
    resolved_default_destination,
)
from .progress import ProgressEvent, ProgressSink

__all__ = [
    "BackupError", "Result", "configuration_fingerprint", "main", "parse_args",
    "run", "source_fingerprints", "verify_archive", "SetupConfig",
    "build_setup_config", "initialize_destination", "resolved_default_destination",
    "rollback_initialized_destination", "InitializationLedger",
    "ProgressEvent", "ProgressSink",
]
__version__ = "0.1.0-beta"
