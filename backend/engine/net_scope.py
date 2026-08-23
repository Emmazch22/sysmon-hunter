"""Destination-scope classification, shared by the statistical detectors.

Both beacon.py and scan.py hit the same question: is this destination
infrastructure inside the network, or the open internet? A perfectly
periodic connection and a wide fan-out both mean something different
depending on the answer, and both detectors weigh it into severity the
same way (see each module's docstring for why), so the classification
itself lives in one place rather than two copies drifting apart.
"""

from __future__ import annotations

import ipaddress


def is_internal(destination_ip: str) -> bool:
    """Is this destination private, loopback, or link-local rather than the
    open internet?

    An address that fails to parse (a hostname Sysmon occasionally logs
    instead of an IP) is treated as external rather than silently downgraded,
    since "unknown" should never read as "safe".
    """
    try:
        addr = ipaddress.ip_address(destination_ip)
    except ValueError:
        return False
    return addr.is_private or addr.is_loopback or addr.is_link_local
