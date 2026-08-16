"""Enable ``python -m har_sanitizer ...``."""

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
