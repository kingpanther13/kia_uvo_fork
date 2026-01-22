"""
Monkeypatch fixes for hyundai_kia_connect_api library.

This module patches the KiaUvoApiUSA class to handle API changes where
rmtoken is no longer returned in the OTP verification response headers.
"""

import logging
import datetime as dt
import sys

_LOGGER = logging.getLogger(__name__)

# Track if patches have been applied
_PATCHES_APPLIED = False


def _patched_verify_otp(self, otp_key: str, otp_code: str, xid: str) -> tuple[str, str]:
    """
    Patched version of _verify_otp that handles missing rmtoken.

    Kia's API has changed and no longer consistently returns rmtoken in the
    OTP verification response headers. This patch:
    1. Tries to get rmtoken from headers (original behavior)
    2. If not found, checks the JSON response body
    3. If still not found, uses sid as fallback
    """
    from hyundai_kia_connect_api.const import DOMAIN

    _LOGGER.warning(f"{DOMAIN} - PATCHED _verify_otp is running!")

    url = self.API_URL + "cmm/verifyOTP"
    headers = self.api_headers()
    headers["otpkey"] = otp_key
    headers["xid"] = xid
    data = {"otp": otp_code}

    _LOGGER.debug(f"{DOMAIN} - Sending OTP verification request to {url}")
    response = self.session.post(url, json=data, headers=headers)
    _LOGGER.warning(f"{DOMAIN} - Verify OTP Response: {response.text}")
    _LOGGER.warning(f"{DOMAIN} - Verify OTP Response Headers: {dict(response.headers)}")

    response_json = response.json()

    # Check for errors
    status_code = response_json.get("status", {}).get("statusCode", -1)
    if status_code != 0:
        error_msg = response_json.get("status", {}).get("errorMessage", "Unknown error")
        _LOGGER.error(f"{DOMAIN} - OTP verification failed with status {status_code}: {error_msg}")
        raise Exception(f"{DOMAIN} - OTP verification failed: {error_msg}")

    # Try to get sid from multiple locations
    sid = response.headers.get("sid")
    if not sid:
        sid = response_json.get("sid")
    if not sid:
        payload = response_json.get("payload", {})
        if payload:
            sid = payload.get("sid")

    # Try to get rmtoken from multiple locations
    rmtoken = response.headers.get("rmtoken")
    if not rmtoken:
        rmtoken = response_json.get("rmtoken")
    if not rmtoken:
        payload = response_json.get("payload", {})
        if payload:
            rmtoken = payload.get("rmtoken")

    if not sid:
        raise Exception(
            f"{DOMAIN} - No sid in OTP verification response. "
            f"Headers: {dict(response.headers)}, Body: {response_json}"
        )

    if not rmtoken:
        _LOGGER.warning(
            f"{DOMAIN} - No rmtoken in OTP verification response. "
            "Using sid as fallback for rmtoken."
        )
        rmtoken = sid

    _LOGGER.warning(f"{DOMAIN} - OTP Verify extracted sid: {sid[:8]}..., rmtoken: {rmtoken[:8] if rmtoken else 'None'}...")
    return sid, rmtoken


def _patched_complete_login_with_otp(
    self, username: str, password: str, sid: str, rmtoken: str
) -> str:
    """
    Patched version of _complete_login_with_otp with better error handling.
    """
    from hyundai_kia_connect_api.const import DOMAIN

    _LOGGER.warning(f"{DOMAIN} - PATCHED _complete_login_with_otp is running!")

    url = self.API_URL + "prof/authUser"
    data = {
        "deviceKey": self.device_id,
        "deviceType": 2,
        "userCredential": {"userId": username, "password": password},
    }
    headers = self.api_headers()
    headers["sid"] = sid

    if rmtoken:
        headers["rmtoken"] = rmtoken

    _LOGGER.debug(f"{DOMAIN} - Completing login with sid={sid[:8]}...")

    response = self.session.post(url, json=data, headers=headers)
    _LOGGER.warning(f"{DOMAIN} - Complete Login Response: {response.text}")
    _LOGGER.warning(f"{DOMAIN} - Complete Login Response Headers: {dict(response.headers)}")

    response_json = response.json()

    status = response_json.get("status", {})
    if status.get("statusCode", 0) != 0:
        error_msg = status.get("errorMessage", "Unknown error")
        _LOGGER.error(f"{DOMAIN} - Complete login failed: {error_msg}")
        raise Exception(f"{DOMAIN} - Complete login failed: {error_msg}")

    final_sid = response.headers.get("sid")
    if not final_sid:
        final_sid = response_json.get("sid")
    if not final_sid:
        payload = response_json.get("payload", {})
        if payload:
            final_sid = payload.get("sid")

    if not final_sid:
        raise Exception(
            f"{DOMAIN} - No final sid returned. "
            f"Response: {response.text}, Headers: {dict(response.headers)}"
        )

    _LOGGER.warning(f"{DOMAIN} - Complete login successful, got final sid: {final_sid[:8]}...")
    return final_sid


def _patched_verify_otp_and_complete_login(
    self,
    username: str,
    password: str,
    otp_code: str,
    otp_request,
    pin: str | None,
):
    """
    Patched version of verify_otp_and_complete_login with improved error handling.
    """
    from hyundai_kia_connect_api.Token import Token
    from hyundai_kia_connect_api.const import DOMAIN, LOGIN_TOKEN_LIFETIME

    _LOGGER.warning(f"{DOMAIN} - PATCHED verify_otp_and_complete_login is running!")

    sid, rmtoken = self._verify_otp(
        otp_request.otp_key, otp_code, otp_request.request_id
    )

    _LOGGER.debug(f"{DOMAIN} - OTP verified, completing login...")
    final_sid = self._complete_login_with_otp(username, password, sid, rmtoken)

    _LOGGER.warning(f"{DOMAIN} - OTP login completed successfully!")

    valid_until = dt.datetime.now(dt.timezone.utc) + LOGIN_TOKEN_LIFETIME

    return Token(
        username=username,
        password=password,
        access_token=final_sid,
        refresh_token=rmtoken if rmtoken else final_sid,
        valid_until=valid_until,
        device_id=self.device_id,
        pin=pin,
    )


def apply_patches():
    """Apply all patches to the KiaUvoApiUSA class."""
    global _PATCHES_APPLIED

    if _PATCHES_APPLIED:
        return

    # Use print() to ensure this shows up no matter what logging config is set
    print("=" * 60)
    print("KIA_UVO PATCH: APPLYING KIAUVOAPIUSA PATCHES FOR OTP HANDLING")
    print("=" * 60)

    # Import the class to patch
    from hyundai_kia_connect_api.KiaUvoApiUSA import KiaUvoApiUSA

    # Apply patches
    KiaUvoApiUSA._verify_otp = _patched_verify_otp
    KiaUvoApiUSA._complete_login_with_otp = _patched_complete_login_with_otp
    KiaUvoApiUSA.verify_otp_and_complete_login = _patched_verify_otp_and_complete_login

    # Mark a flag on the class so we can verify patches are active
    KiaUvoApiUSA._kia_uvo_patches_applied = True

    _PATCHES_APPLIED = True

    print("KIA_UVO PATCH: Patches applied successfully!")
    print(f"KIA_UVO PATCH: verify_otp_and_complete_login = {KiaUvoApiUSA.verify_otp_and_complete_login}")
    print("=" * 60)


def verify_patches_applied():
    """Verify patches are applied, raise error if not."""
    from hyundai_kia_connect_api.KiaUvoApiUSA import KiaUvoApiUSA

    if not getattr(KiaUvoApiUSA, '_kia_uvo_patches_applied', False):
        raise RuntimeError(
            "KIA_UVO PATCH ERROR: Patches were not applied to KiaUvoApiUSA! "
            "The OTP fix will not work. Please report this issue."
        )
