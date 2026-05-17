"""
cross_check.py
--------------
Cross-checks Business/Residential IPs against ipapi.is.
Rules:
  is_datacenter = true      → type = "Hosting"
  is_mobile     = true      → type = "Wireless"
  company.type  = "isp"     → type = "ISP"
Corrected rows flagged with _api_corrected=True (shown orange in UI).
"""

import time
import requests
import streamlit as st
import pandas as pd

BATCH_SIZE = 1000


def verify_business_ips(df: pd.DataFrame, df_white: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df["_api_corrected"] = False

    if df.empty:
        return df

    white_ips = set(df_white["ipAddress"].unique()) if not df_white.empty else set()

    mask = (
            (~df["ipAddress"].isin(white_ips)) &
            (df["type"].fillna("").str.lower().isin(["business", "residential"]))
    )

    ips_to_check = df[mask]["ipAddress"].unique().tolist()

    if not ips_to_check:
        return df

    corrected_ips = {}

    for i in range(0, len(ips_to_check), BATCH_SIZE):
        batch = ips_to_check[i:i + BATCH_SIZE]

        try:
            response = requests.post(
                "https://api.ipapi.is",
                json={"ips": batch},
                timeout=30,
            )

            if response.status_code == 200:
                data = response.json()
                for ip in batch:
                    ip_data = data.get(ip, {})
                    if not ip_data:
                        continue

                    company_type = (ip_data.get("company") or {}).get("type", "").lower()

                    if ip_data.get("is_datacenter") is True:
                        corrected_ips[ip] = "Hosting"
                    elif ip_data.get("is_mobile") is True:
                        corrected_ips[ip] = "Wireless"

            elif response.status_code == 429:
                st.warning("ipapi.is rate limit reached, waiting 60s...")
                time.sleep(60)

        except Exception as e:
            print(f"ipapi.is error: {e}")

    for ip, new_type in corrected_ips.items():
        update_mask = (df["ipAddress"] == ip) & mask
        df.loc[update_mask, "type"] = new_type
        df.loc[update_mask, "_api_corrected"] = True

    print(f"Business/Residential IP sayısı: {mask.sum()}")
    print(f"Corrected IPs: {corrected_ips}")

    return df