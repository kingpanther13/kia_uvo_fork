"""
Monkeypatch fixes for hyundai_kia_connect_api library.

This module patches the KiaUvoApiUSA class to handle API changes where
rmtoken is no longer returned in the OTP verification response headers.
"""

import logging
import datetime as dt

from hyundai_kia_connect_api.KiaUvoApiUSA import KiaUvoApiUSA
from hyundai_kia_connect_api.Token import Token
from hyundai_kia_connect_api.const import DOMAIN, LOGIN_TOKEN_LIFETIME

_LOGGER = logging.getLogger(__name__)


def _patched_verify_otp(self, otp_key: str, otp_code: str, xid: str) -> tuple[str, str]:
    """
    Patched version of _verify_otp that handles missing rmtoken.

    Kia's API has changed and no longer consistently returns rmtoken in the
    OTP verification response headers. This patch:
    1. Tries to get rmtoken from headers (original behavior)
    2. If not found, checks the JSON response body
    3. If still not found, uses an empty string and attempts to proceed
    """
    url = self.API_URL + "cmm/verifyOTP"
    headers = self.api_headers()
    headers["otpkey"] = otp_key
    headers["xid"] = xid
    data = {"otp": otp_code}

    response = self.session.post(url, json=data, headers=headers)
    _LOGGER.debug(f"{DOMAIN} - Verify OTP Response: {response.text}")
    _LOGGER.debug(f"{DOMAIN} - Verify OTP Response Headers: {dict(response.headers)}")

    response_json = response.json()

    if response_json.get("status", {}).get("statusCode", -1) != 0:
        error_msg = response_json.get("status", {}).get("errorMessage", "Unknown error")
        raise Exception(f"{DOMAIN} - OTP verification failed: {error_msg}")

    # Try to get sid from headers first, then from response body
    sid = response.headers.get("sid")
    if not sid:
        sid = response_json.get("sid")
    if not sid:
        # Check if it's in the payload
        payload = response_json.get("payload", {})
        sid = payload.get("sid")

    # Try to get rmtoken from headers first, then from response body
    rmtoken = response.headers.get("rmtoken")
    if not rmtoken:
        rmtoken = response_json.get("rmtoken")
    if not rmtoken:
        # Check if it's in the payload
        payload = response_json.get("payload", {})
        rmtoken = payload.get("rmtoken")

    if not sid:
        raise Exception(
            f"{DOMAIN} - No sid in OTP verification response. "
            f"Headers: {dict(response.headers)}, Body: {response_json}"
        )

    if not rmtoken:
        _LOGGER.warning(
            f"{DOMAIN} - No rmtoken in OTP verification response. "
            "Attempting to proceed without it. This may fail if the API requires it."
        )
        # Use sid as rmtoken fallback - some API versions accept this
        rmtoken = sid

    _LOGGER.debug(f"{DOMAIN} - OTP Verify extracted sid: {sid}, rmtoken: {rmtoken}")
    return sid, rmtoken


def _patched_complete_login_with_otp(
    self, username: str, password: str, sid: str, rmtoken: str
) -> str:
    """
    Patched version of _complete_login_with_otp with better error handling.

    Handles cases where rmtoken might be empty or invalid.
    """
    url = self.API_URL + "prof/authUser"
    data = {
        "deviceKey": self.device_id,
        "deviceType": 2,
        "userCredential": {"userId": username, "password": password},
    }
    headers = self.api_headers()
    headers["sid"] = sid

    # Only add rmtoken header if we have one
    if rmtoken:
        headers["rmtoken"] = rmtoken

    _LOGGER.debug(f"{DOMAIN} - Complete login headers: sid={sid}, rmtoken={rmtoken}")

    response = self.session.post(url, json=data, headers=headers)
    _LOGGER.debug(f"{DOMAIN} - Complete Login Response: {response.text}")
    _LOGGER.debug(f"{DOMAIN} - Complete Login Response Headers: {dict(response.headers)}")

    response_json = response.json()

    # Check for errors in response
    status = response_json.get("status", {})
    if status.get("statusCode", 0) != 0:
        error_msg = status.get("errorMessage", "Unknown error")
        _LOGGER.error(f"{DOMAIN} - Complete login failed: {error_msg}")
        raise Exception(f"{DOMAIN} - Complete login failed: {error_msg}")

    # Try to get final_sid from headers first, then response body
    final_sid = response.headers.get("sid")
    if not final_sid:
        final_sid = response_json.get("sid")
    if not final_sid:
        payload = response_json.get("payload", {})
        final_sid = payload.get("sid")

    if not final_sid:
        raise Exception(
            f"{DOMAIN} - No final sid returned. "
            f"Response: {response.text}, Headers: {dict(response.headers)}"
        )

    return final_sid


def _patched_verify_otp_and_complete_login(
    self,
    username: str,
    password: str,
    otp_code: str,
    otp_request,
    pin: str | None,
) -> Token:
    """
    Patched version of verify_otp_and_complete_login with improved error handling.
    """
    _LOGGER.debug(f"{DOMAIN} - Starting OTP verification and login completion")

    sid, rmtoken = self._verify_otp(
        otp_request.otp_key, otp_code, otp_request.request_id
    )

    _LOGGER.debug(f"{DOMAIN} - OTP verified, completing login...")
    final_sid = self._complete_login_with_otp(username, password, sid, rmtoken)

    _LOGGER.debug(f"{DOMAIN} - OTP login successful, obtained final session id")

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
    _LOGGER.info(f"{DOMAIN} - Applying KiaUvoApiUSA patches for OTP handling")

    # Patch the methods
    KiaUvoApiUSA._verify_otp = _patched_verify_otp
    KiaUvoApiUSA._complete_login_with_otp = _patched_complete_login_with_otp
    KiaUvoApiUSA.verify_otp_and_complete_login = _patched_verify_otp_and_complete_login

    _LOGGER.info(f"{DOMAIN} - KiaUvoApiUSA patches applied successfully")
