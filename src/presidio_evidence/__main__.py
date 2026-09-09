"""``python -m presidio_evidence`` — same entry point as the ``presidio-evidence`` script."""

from ._cli import main

raise SystemExit(main())
