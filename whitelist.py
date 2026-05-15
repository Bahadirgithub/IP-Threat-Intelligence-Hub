import os
import requests
import pandas as pd
from dotenv import load_dotenv

load_dotenv()

GN_API_KEY = os.getenv("GREYNOISE_API_KEY")
BATCH_SIZE = 1000

WHITELIST_ASNS = {
    20473, 44907, 398324, 398722, 211680, 8190, 197832, 49889, 27176, 206264,
    203037, 208843, 36375, 7377, 680, 1249, 32, 6541, 3, 559, 2500, 29789,
    30148, 40627, 393667, 1101, 3334, 33872, 2515, 8308, 211298
}

def check_whitelist(df: pd.DataFrame) -> tuple:
    if df.empty:
        return pd.DataFrame(), 0, 0

    # --- STEP 1: Manual ASN Check ---
    def is_asn_whitelisted(row):
        raw_asn = str(row.get("asn", ""))
        clean_asn = "".join(filter(str.isdigit, raw_asn))
        return clean_asn and int(clean_asn) in WHITELIST_ASNS

    df_asn_match = df[df.apply(is_asn_whitelisted, axis=1)].copy()
    asn_count = len(df_asn_match)

    # --- STEP 2: GreyNoise API Check ---
    remaining_df = df[~df["ipAddress"].isin(df_asn_match["ipAddress"])]
    whitelisted_by_gn_ips = []

    if GN_API_KEY and not remaining_df.empty:
        ips_to_check = remaining_df["ipAddress"].unique().tolist()
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": f"Bearer {GN_API_KEY}" # Not: V3 anahtarın 'key' mi yoksa 'Authorization' mı istiyor kontrol et!
        }

        for i in range(0, len(ips_to_check), BATCH_SIZE):
            batch = ips_to_check[i:i + BATCH_SIZE]
            try:
                response = requests.post(
                    "https://api.greynoise.io/v2/noise/multi/quick", # Batch için V2 genelde daha stabildir
                    headers=headers,
                    json={"ips": batch},
                    timeout=30
                )

                if response.status_code == 200:
                    data = response.json()
                    # Liste gelmezse hata vermemesi için koruma
                    results = data if isinstance(data, list) else data.get("data", [])

                    for res in results:
                        # 1. Önce sınıflandırmaya bak (Hızlı eleme)
                        classification = (res.get("classification") or "").lower()

                        if classification == "benign":
                            # 2. Eğer benign ise ismi temizle ve kontrol et
                            name = res.get("name") or ""
                            clean_name = name.replace('"', '').lower().strip()

                            if clean_name and clean_name != "unknown":
                                whitelisted_by_gn_ips.append(res.get("ip"))

            except Exception as e:
                print(f"GreyNoise API error: {e}")

    df_gn_match = remaining_df[remaining_df["ipAddress"].isin(whitelisted_by_gn_ips)].copy()
    gn_count = len(df_gn_match)

    final_whitelist = pd.concat([df_asn_match, df_gn_match]).drop_duplicates(subset=["ipAddress"])

    return final_whitelist, asn_count, gn_count