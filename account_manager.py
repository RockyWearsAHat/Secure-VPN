"""
Account Manager Integration

Validates VPN users against the selfhost admin API's own
`POST /api/vpn/check-access` (crates/app/admin/src/vpn_api.rs) — the same
capability grants (`vpn.access:<location>`) the admin console itself
enforces, rather than a separate account system this server invents and
nothing else agrees with.
"""

import asyncio
import aiohttp
import logging
from pathlib import Path
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)


class AccountManager:
    """Client for the selfhost admin API's VPN access check."""

    def __init__(self, base_url: str, token: str, timeout: int = 5):
        """
        Args:
            base_url: Base URL of the admin API's loopback listener, e.g.
                http://127.0.0.1:9191 — plain HTTP, never TLS. It never
                leaves the box; crates/app/cli/src/doctor.rs's own client
                talks to the same address the same way.
            token: The deployment's bearer token (<data_dir>/admin.token),
                the same credential the CLI and console client present.
                Every admin API route demands it, or a session cookie.
            timeout: Request timeout in seconds.
        """
        self.base_url = base_url.rstrip('/')
        self.token = token
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.session: Optional[aiohttp.ClientSession] = None

    async def __aenter__(self):
        """Context manager entry."""
        self.session = aiohttp.ClientSession(timeout=self.timeout)
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        if self.session:
            await self.session.close()

    async def validate_user(
        self, user_id: str, location: str, ip_address: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Ask the admin API whether `user_id` holds `vpn.access:<location>`.

        Fails closed: a connection error, a timeout, or a non-200 response
        denies access rather than admitting a user this process could not
        actually ask about. The admin API itself answers 200 for every
        outcome it has an opinion on — allowed or not, known user or not,
        known location or not (see vpn_api.rs) — so a non-200 here means
        something between this process and the admin API broke, not that
        the deployment said no.

        Args:
            user_id: The peer's identity, exactly as `state.peer_name` names
                it — the same string `PersonName` on the admin side expects.
            location: Which VPN location this relay is (e.g. "console",
                "ai-studio") — this process's own `--location`, not
                something the client claims.
            ip_address: Client IP address, for logging only.

        Returns:
            Dict with keys:
            - valid (bool): Whether access is granted
            - reason (str): Why access was allowed/denied
        """
        if not self.session:
            return {"valid": False, "reason": "account manager client not initialised"}

        try:
            url = f"{self.base_url}/api/vpn/check-access"
            headers = {"Authorization": f"Bearer {self.token}"}
            payload = {"user_id": user_id, "location_id": location}

            async with self.session.post(url, json=payload, headers=headers) as resp:
                if resp.status != 200:
                    logger.warning(
                        f"admin API returned {resp.status} checking '{user_id}' at '{location}'"
                    )
                    return {
                        "valid": False,
                        "reason": f"admin API error: {resp.status} (fail-secure: denying access)",
                    }

                data = await resp.json()
                allowed = bool(data.get("allowed"))
                if allowed:
                    logger.info(f"'{user_id}' granted vpn.access:{location} by the admin API")
                else:
                    logger.warning(f"'{user_id}' denied at '{location}': {data.get('reason')}")
                return {"valid": allowed, "reason": data.get("reason", "")}

        except asyncio.TimeoutError:
            logger.error(f"admin API timeout validating '{user_id}' at '{location}'")
            return {
                "valid": False,
                "reason": "admin API timeout (fail-secure: denying access)",
            }
        except Exception as e:
            logger.error(f"admin API error validating '{user_id}' at '{location}': {e}")
            return {
                "valid": False,
                "reason": f"admin API error: {e} (fail-secure: denying access)",
            }


# Global account manager instance (created once at server startup)
_account_manager: Optional[AccountManager] = None


def _read_token(token_file: str) -> str:
    """
    Reads the deployment's bearer token from disk.

    Read once at startup rather than per request: the file is owner-only
    (crates/app/admin/src/token.rs) and does not rotate under a running
    daemon, so re-reading it on every handshake would just be a syscall
    nothing else in this server pays for a credential.
    """
    return Path(token_file).read_text(encoding="utf-8").strip()


async def init_account_manager(base_url: str, token_file: str) -> None:
    """Initialize the global account manager client."""
    global _account_manager
    try:
        token = _read_token(token_file)
    except OSError as e:
        # No token still fails closed — a request with no Authorization
        # header gets the same refusal as a wrong one — but says so loudly
        # instead of looking like every peer's own credential is bad.
        logger.error(f"could not read bearer token at {token_file}: {e}")
        token = ""
    _account_manager = AccountManager(base_url, token)
    await _account_manager.__aenter__()
    logger.info(f"Account manager initialized at {base_url}")


async def shutdown_account_manager() -> None:
    """Shutdown the global account manager client."""
    global _account_manager
    if _account_manager:
        await _account_manager.__aexit__(None, None, None)
        _account_manager = None
        logger.info("Account manager shut down")


async def validate_vpn_user(
    user_id: str, location: str, ip_address: Optional[str] = None
) -> Dict[str, Any]:
    """Validate a VPN user's access to one location."""
    if not _account_manager:
        return {"valid": False, "reason": "account manager not initialised"}
    return await _account_manager.validate_user(user_id, location, ip_address)
