"""Terminal encoding safety for all CLI output."""
import sys


def configure_output():
    """Call once at CLI startup to ensure safe Unicode output."""
    if hasattr(sys.stdout, 'reconfigure'):
        try:
            sys.stdout.reconfigure(encoding='utf-8', errors='replace')
            sys.stderr.reconfigure(encoding='utf-8', errors='replace')
        except (AttributeError, OSError):
            pass
