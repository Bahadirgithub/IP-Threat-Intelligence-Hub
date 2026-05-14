import pandas as pd

# Trusted Autonomous System Numbers (ASNs) for scanners and academic institutions
WHITELIST_ASNS = {
    20473, 44907, 398324, 398722, 211680, 8190, 197832, 49889, 27176, 206264,
    203037, 208843, 36375, 7377, 680, 1249, 32, 6541, 3, 559, 2500, 29789,
    30148, 40627, 393667, 1101, 3334, 33872, 2515, 8308, 211298
}

def check_whitelist(df: pd.DataFrame) -> pd.DataFrame:
    """Matches IPs against trusted ASNs."""
    if df.empty:
        return pd.DataFrame()

    def is_whitelisted(row):
        raw_asn = str(row.get("asn", ""))
        # Extract numeric part only (e.g., "AS1234" -> "1234")
        clean_asn = "".join(filter(str.isdigit, raw_asn))
        if clean_asn and int(clean_asn) in WHITELIST_ASNS:
            return True
        return False

    return df[df.apply(is_whitelisted, axis=1)].copy()