"""
Account Manager Integration

Validates VPN users against the account-manager service.
Checks if a user has VPN access and retrieves their subdomain permissions.
"""

import asyncio
import aiohttp
import logging
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)


class AccountManager:
    """Client for account-manager API."""

    def __init__(self, base_url: str = "http://127.0.0.1:9000", timeout: int = 5):
        """
        Initialize account-manager client.

        Args:
            base_url: Base URL of account-manager service
            timeout: Request timeout in seconds
        """
        self.base_url = base_url.rstrip('/')
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

    async def validate_user(self, user_id: str, ip_address: Optional[str] = None) -> Dict[str, Any]:
        """
        Validate if a user has VPN access.

        This checks if the user exists and is active in the account-manager.
        Used after certificate-based authentication to verify the user is still valid.

        Args:
            user_id: The user's name/identifier (e.g., "dad" from peer roster)
            ip_address: Client IP address for logging

        Returns:
            Dict with keys:
            - valid (bool): Whether user is authorized
            - user_id (str): The validated user ID
            - permissions (list): List of accessible subdomains
            - reason (str): Authorization reason or denial reason
            - timeout (int): Session timeout in seconds
        """
        if not self.session:
            return {
                "valid": False,
                "user_id": user_id,
                "permissions": [],
                "reason": "Account manager client not initialized",
                "timeout": 0
            }

        try:
            # Query account-manager for user validation
            # For now, this just checks if the user exists
            # In future, this can check VPN-specific tokens or permissions

            url = f"{self.base_url}/api/users"
            async with self.session.get(url) as resp:
                if resp.status != 200:
                    logger.warning(f"Account manager returned {resp.status}")
                    return {
                        "valid": False,
                        "user_id": user_id,
                        "permissions": [],
                        "reason": f"Account manager error: {resp.status}",
                        "timeout": 0
                    }

                users = await resp.json()

                # Look for user in the list
                user_found = any(u.get('username') == user_id for u in users)

                if user_found:
                    logger.info(f"User '{user_id}' validated by account-manager")
                    return {
                        "valid": True,
                        "user_id": user_id,
                        "permissions": [],  # Future: fetch user's subdomain permissions
                        "reason": "User has VPN access",
                        "timeout": 86400  # 24 hours
                    }
                else:
                    logger.warning(f"User '{user_id}' not found in account-manager")
                    return {
                        "valid": False,
                        "user_id": user_id,
                        "permissions": [],
                        "reason": "User not found in account-manager",
                        "timeout": 0
                    }

        except asyncio.TimeoutError:
            logger.error(f"Account manager validation timeout for user '{user_id}'")
            return {
                "valid": False,
                "user_id": user_id,
                "permissions": [],
                "reason": "Account manager timeout (fail-secure: denying access)",
                "timeout": 0
            }
        except Exception as e:
            logger.error(f"Account manager validation error for user '{user_id}': {e}")
            # Fail-secure: deny on any error
            return {
                "valid": False,
                "user_id": user_id,
                "permissions": [],
                "reason": f"Account manager error: {str(e)}",
                "timeout": 0
            }

    async def check_subdomain_access(
        self,
        user_id: str,
        subdomain: str,
        ip_address: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Check if a user can access a specific subdomain.

        Called when a user's traffic targets a specific subdomain,
        to enforce granular access control beyond just VPN access.

        Args:
            user_id: The user's identifier
            subdomain: Target subdomain/site name
            ip_address: Client IP address for logging

        Returns:
            Dict with keys:
            - allowed (bool): Whether access is granted
            - reason (str): Why access was allowed/denied
            - timeout (int): Session timeout in seconds
        """
        if not self.session:
            return {
                "allowed": False,
                "reason": "Account manager client not initialized",
                "timeout": 0
            }

        try:
            url = f"{self.base_url}/api/vpn/check-subdomain-access"
            payload = {
                "user_id": user_id,
                "subdomain": subdomain,
                "ip_address": ip_address
            }

            async with self.session.post(url, json=payload) as resp:
                if resp.status != 200:
                    logger.warning(f"Account manager returned {resp.status} for subdomain check")
                    return {
                        "allowed": False,
                        "reason": f"Account manager error: {resp.status}",
                        "timeout": 0
                    }

                data = await resp.json()
                return data

        except asyncio.TimeoutError:
            logger.error(f"Subdomain check timeout for user '{user_id}' → '{subdomain}'")
            return {
                "allowed": False,
                "reason": "Subdomain check timeout (fail-secure: denying access)",
                "timeout": 0
            }
        except Exception as e:
            logger.error(f"Subdomain check error: {e}")
            return {
                "allowed": False,
                "reason": f"Check failed: {str(e)}",
                "timeout": 0
            }


# Global account manager instance (created once at server startup)
_account_manager: Optional[AccountManager] = None


async def init_account_manager(base_url: str = "http://127.0.0.1:9000"):
    """Initialize the global account manager client."""
    global _account_manager
    _account_manager = AccountManager(base_url)
    await _account_manager.__aenter__()
    logger.info(f"Account manager initialized at {base_url}")


async def shutdown_account_manager():
    """Shutdown the global account manager client."""
    global _account_manager
    if _account_manager:
        await _account_manager.__aexit__(None, None, None)
        _account_manager = None
        logger.info("Account manager shut down")


async def validate_vpn_user(user_id: str, ip_address: Optional[str] = None) -> Dict[str, Any]:
    """Validate VPN user access."""
    if not _account_manager:
        return {
            "valid": False,
            "user_id": user_id,
            "permissions": [],
            "reason": "Account manager not initialized",
            "timeout": 0
        }
    return await _account_manager.validate_user(user_id, ip_address)


async def check_subdomain_access(
    user_id: str,
    subdomain: str,
    ip_address: Optional[str] = None
) -> Dict[str, Any]:
    """Check user access to a subdomain."""
    if not _account_manager:
        return {
            "allowed": False,
            "reason": "Account manager not initialized",
            "timeout": 0
        }
    return await _account_manager.check_subdomain_access(user_id, subdomain, ip_address)
