"""Correct Business/Residential IP types using ipapi.is, capped per run."""

import os
from pathlib import Path

import pandas as pd
import requests
import streamlit as st
from dotenv import load_dotenv

ENV_FILE = Path(__file__).resolve().parent / ".env"
load_dotenv(dotenv_path=ENV_FILE)

IPAPI_IS_API_KEY = (
        os.getenv("IPAPI_IS_API_KEY", "").strip()
        or os.getenv("IPAPI_IS_KEY", "").strip()
)
API_URL = "https://api.ipapi.is"
BATCH_SIZE = 100
MAX_IPS_PER_RUN = 1000
REQUEST_TIMEOUT = 30


def _response_error(response: requests.Response) -> str:
    """Return a short API error without exposing the API key."""
    try:
        body = response.json()
    except ValueError:
        body = response.text[:500]

    if isinstance(body, dict):
        code = body.get("error_code")
        message = body.get("error")
        if code and message:
            return f"{code}: {message}"
        if code:
            return str(code)
        if message:
            return str(message)
    return str(body) or f"HTTP {response.status_code}"


def verify_business_ips(df: pd.DataFrame, df_white: pd.DataFrame) -> pd.DataFrame:
    """Check at most 1,000 unique eligible IPs per function run."""
    df = df.copy()
    df["_api_corrected"] = False

    if df.empty:
        return df

    if "ipAddress" not in df.columns or "type" not in df.columns:
        st.warning("ipapi.is check skipped: required columns 'ipAddress' and/or 'type' are missing.")
        return df

    white_ips = (
        set(df_white["ipAddress"].dropna().astype(str).unique())
        if not df_white.empty and "ipAddress" in df_white.columns
        else set()
    )
    mask = (
            ~df["ipAddress"].astype(str).isin(white_ips)
            & df["type"].fillna("").astype(str).str.lower().isin(["business", "residential"])
    )
    ips_to_check = df.loc[mask, "ipAddress"].dropna().astype(str).unique().tolist()

    if not ips_to_check:
        return df

    if not IPAPI_IS_API_KEY:
        st.warning(f"ipapi.is API key missing. Add IPAPI_IS_API_KEY=your_key to {ENV_FILE}.")
        print("[cross_check] API key missing; skipped IP checks.")
        return df

    corrected_ips: dict[str, str] = {}
    warning_placeholder = st.empty()
    checked_this_run = 0
    limit_reached = len(ips_to_check) > MAX_IPS_PER_RUN
    api_failed = False
    ips_to_check = ips_to_check[:MAX_IPS_PER_RUN]

    for offset in range(0, len(ips_to_check), BATCH_SIZE):
        batch = ips_to_check[offset:offset + BATCH_SIZE]
        batch_num = offset // BATCH_SIZE + 1
        print(f"[cross_check] Batch {batch_num}: sending {len(batch)} IPs (limit {MAX_IPS_PER_RUN} per run).")

        try:
            response = requests.post(
                API_URL,
                json={"ips": batch, "key": IPAPI_IS_API_KEY},
                headers={"Content-Type": "application/json"},
                timeout=REQUEST_TIMEOUT,
            )
            checked_this_run += len(batch)

            if response.status_code == 200:
                data = response.json()
                if not isinstance(data, dict):
                    raise ValueError("Response JSON is not an object.")
                for ip in batch:
                    ip_data = data.get(ip, {})
                    if not isinstance(ip_data, dict):
                        continue
                    if ip_data.get("is_datacenter") is True:
                        corrected_ips[ip] = "Hosting"
                    elif ip_data.get("is_mobile") is True:
                        corrected_ips[ip] = "Wireless"
            elif response.status_code == 429:
                error = _response_error(response)
                warning_placeholder.warning(
                    f"ipapi.is quota/rate limit reached. Remaining checks were stopped. Details: {error}"
                )
                print(f"[cross_check] HTTP 429; stopped: {error}")
                api_failed = True
                break
            elif response.status_code == 403:
                error = _response_error(response)
                warning_placeholder.error(
                    f"ipapi.is refused the request. Check the API key/account. Details: {error}"
                )
                print(f"[cross_check] HTTP 403; stopped: {error}")
                api_failed = True
                break
            else:
                error = _response_error(response)
                warning_placeholder.warning(
                    f"ipapi.is request failed (HTTP {response.status_code}). "
                    f"Remaining checks were stopped. Details: {error}"
                )
                print(f"[cross_check] HTTP {response.status_code}; stopped: {error}")
                api_failed = True
                break
        except (requests.RequestException, ValueError) as exc:
            warning_placeholder.warning(
                f"ipapi.is request/response failed. Remaining checks were stopped; the app will continue. ({exc})"
            )
            print(f"[cross_check] Request/response error; stopped: {exc}")
            api_failed = True
            break


    for ip, new_type in corrected_ips.items():
        update_mask = (df["ipAddress"].astype(str) == ip) & mask
        df.loc[update_mask, "type"] = new_type
        df.loc[update_mask, "_api_corrected"] = True

    if limit_reached and not api_failed:
        warning_placeholder.warning(
            f"Only the first {MAX_IPS_PER_RUN} unique IPs were checked in this run; "
            "the remaining IPs were skipped. The app will continue."
        )

    print(
        f"[cross_check] IPs submitted this run: {checked_this_run}; "
        f"corrected: {len(corrected_ips)}; limit_reached={limit_reached}; api_failed={api_failed}"
    )
    return df
