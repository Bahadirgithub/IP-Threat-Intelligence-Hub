"""
cross_check.py
--------------
Cross-checks Business/Residential IPs against ipapi.is.
Rules:
  is_datacenter = true → type = "Hosting"
  is_mobile     = true → type = "Wireless"
Corrected rows flagged with _api_corrected=True (shown orange in UI).
"""

import time
import requests
import streamlit as st
import pandas as pd

BATCH_SIZE = 100


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
    warning_placeholder = st.empty()  # Tek bir placeholder, bir kez gösterilir

    for i in range(0, len(ips_to_check), BATCH_SIZE):
        batch = ips_to_check[i:i + BATCH_SIZE]
        print(f"[cross_check] Batch {i // BATCH_SIZE + 1}/{(len(ips_to_check) + BATCH_SIZE - 1) // BATCH_SIZE}: {len(batch)} IPs")

        while True:
            try:
                response = requests.post(
                    "https://api.ipapi.is",
                    json={"ips": batch},
                    timeout=30,
                )

                if response.status_code == 200:
                    warning_placeholder.empty()
                    data = response.json()
                    for ip in batch:
                        ip_data = data.get(ip, {})
                        if not ip_data:
                            continue
                        if ip_data.get("is_datacenter") is True:
                            corrected_ips[ip] = "Hosting"
                        elif ip_data.get("is_mobile") is True:
                            corrected_ips[ip] = "Wireless"
                    break

                elif response.status_code == 429:
                    warning_placeholder.warning("⚠️ ipapi.is rate limit reached, waiting 60s...")
                    print(f"[cross_check] Rate limit hit, waiting 60s...")
                    time.sleep(60)

                else:
                    print(f"[cross_check] Unexpected status: {response.status_code}")
                    break

            except Exception as e:
                print(f"[cross_check] ipapi.is error: {e}")
                break

    warning_placeholder.empty()

    for ip, new_type in corrected_ips.items():
        update_mask = (df["ipAddress"] == ip) & mask
        df.loc[update_mask, "type"] = new_type
        df.loc[update_mask, "_api_corrected"] = True

    print(f"[cross_check] Business/Residential IPs checked: {mask.sum()}")
    print(f"[cross_check] Corrected IPs: {len(corrected_ips)}")

    return df