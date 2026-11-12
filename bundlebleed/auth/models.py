from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class AuthSession:
    """A user-supplied session for authenticated crawling.

    `cookie_header` is credential material: never log it, never write it to
    the audit log, a report, or an evidence bundle. Only `name`/`role` may
    ever be used as labels on findings.
    """

    name: str
    role: str
    cookie_header: str

    def __repr__(self) -> str:
        # Defensive: even an accidental print()/repr() in a debugger or log
        # must never leak the cookie value.
        return (
            f"AuthSession(name={self.name!r}, role={self.role!r}, cookie_header='***redacted***')"
        )
