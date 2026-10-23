"""
SecureCloud-X: Machine Learning Feature Engineering
Extracts, formats, and validates user behavior features for the
Isolation Forest anomaly detection engine.
"""

FEATURE_COLUMNS = [
    "failed_login_count",
    "files_accessed",
    "download_count",
    "download_volume_mb",
    "session_duration_min",
    "access_hour",
    "new_ip_flag",
    "new_device_flag",
    "unusual_download_frequency"
]


def create_feature_dict(
    failed_login_count: int = 0,
    files_accessed: int = 1,
    download_count: int = 0,
    download_volume_mb: float = 0.0,
    session_duration_min: float = 10.0,
    access_hour: int = 14,
    new_ip_flag: int = 0,
    new_device_flag: int = 0,
    unusual_download_frequency: int = 0
) -> dict:
    """Creates a standardized feature dictionary for model inference."""
    return {
        "failed_login_count": int(failed_login_count),
        "files_accessed": int(files_accessed),
        "download_count": int(download_count),
        "download_volume_mb": round(float(download_volume_mb), 2),
        "session_duration_min": round(float(session_duration_min), 1),
        "access_hour": int(access_hour),
        "new_ip_flag": int(new_ip_flag),
        "new_device_flag": int(new_device_flag),
        "unusual_download_frequency": int(unusual_download_frequency)
    }


def feature_dict_to_list(features: dict) -> list:
    """Converts a feature dictionary to an ordered numerical list matching FEATURE_COLUMNS."""
    return [features[col] for col in FEATURE_COLUMNS]
