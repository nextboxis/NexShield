"""
ip_lookup.py — IP Geolocation & ASN Intelligence Engine for NexShield
Provides fast, offline-capable IP-to-Country and IP-to-ASN resolution
using datasets from sapics/ip-location-db. Caches results in ip_geo_cache.
"""

import os
import re
import socket
import struct
import bisect
import logging
import threading
from pathlib import Path
from typing import Dict, Any, Optional, Tuple, List
from datetime import datetime, timezone

from config import ip_geo_cache, check_connection  # type: ignore

logger = logging.getLogger(__name__)

_ROOT = Path(__file__).resolve().parent
DATA_DIR = _ROOT / "data" / "ip_location"

COUNTRY_NAMES: Dict[str, str] = {
    "AD": "Andorra", "AE": "United Arab Emirates", "AF": "Afghanistan", "AG": "Antigua and Barbuda",
    "AI": "Anguilla", "AL": "Albania", "AM": "Armenia", "AO": "Angola", "AQ": "Antarctica",
    "AR": "Argentina", "AS": "American Samoa", "AT": "Austria", "AU": "Australia", "AW": "Aruba",
    "AX": "Åland Islands", "AZ": "Azerbaijan", "BA": "Bosnia and Herzegovina", "BB": "Barbados",
    "BD": "Bangladesh", "BE": "Belgium", "BF": "Burkina Faso", "BG": "Bulgaria", "BH": "Bahrain",
    "BI": "Burundi", "BJ": "Benin", "BL": "Saint Barthélemy", "BM": "Bermuda", "BN": "Brunei",
    "BO": "Bolivia", "BQ": "Caribbean Netherlands", "BR": "Brazil", "BS": "Bahamas", "BT": "Bhutan",
    "BV": "Bouvet Island", "BW": "Botswana", "BY": "Belarus", "BZ": "Belize", "CA": "Canada",
    "CC": "Cocos (Keeling) Islands", "CD": "Congo (DRC)", "CF": "Central African Republic",
    "CG": "Congo", "CH": "Switzerland", "CI": "Côte d'Ivoire", "CK": "Cook Islands", "CL": "Chile",
    "CM": "Cameroon", "CN": "China", "CO": "Colombia", "CR": "Costa Rica", "CU": "Cuba",
    "CV": "Cabo Verde", "CW": "Curaçao", "CX": "Christmas Island", "CY": "Cyprus", "CZ": "Czechia",
    "DE": "Germany", "DJ": "Djibouti", "DK": "Denmark", "DM": "Dominica", "DO": "Dominican Republic",
    "DZ": "Algeria", "EC": "Ecuador", "EE": "Estonia", "EG": "Egypt", "EH": "Western Sahara",
    "ER": "Eritrea", "ES": "Spain", "ET": "Ethiopia", "FI": "Finland", "FJ": "Fiji",
    "FK": "Falkland Islands", "FM": "Micronesia", "FO": "Faroe Islands", "FR": "France",
    "GA": "Gabon", "GB": "United Kingdom", "GD": "Grenada", "GE": "Georgia", "GF": "French Guiana",
    "GG": "Guernsey", "GH": "Ghana", "GI": "Gibraltar", "GL": "Greenland", "GM": "Gambia",
    "GN": "Guinea", "GP": "Guadeloupe", "GQ": "Equatorial Guinea", "GR": "Greece",
    "GS": "South Georgia & South Sandwich Islands", "GT": "Guatemala", "GU": "Guam",
    "GW": "Guinea-Bissau", "GY": "Guyana", "HK": "Hong Kong", "HM": "Heard & McDonald Islands",
    "HN": "Honduras", "HR": "Croatia", "HT": "Haiti", "HU": "Hungary", "ID": "Indonesia",
    "IE": "Ireland", "IL": "Israel", "IM": "Isle of Man", "IN": "India",
    "IO": "British Indian Ocean Territory", "IQ": "Iraq", "IR": "Iran", "IS": "Iceland",
    "IT": "Italy", "JE": "Jersey", "JM": "Jamaica", "JO": "Jordan", "JP": "Japan", "KE": "Kenya",
    "KG": "Kyrgyzstan", "KH": "Cambodia", "KI": "Kiribati", "KM": "Comoros", "KN": "Saint Kitts and Nevis",
    "KP": "North Korea", "KR": "South Korea", "KW": "Kuwait", "KY": "Cayman Islands",
    "KZ": "Kazakhstan", "LA": "Laos", "LB": "Lebanon", "LC": "Saint Lucia", "LI": "Liechtenstein",
    "LK": "Sri Lanka", "LR": "Liberia", "LS": "Lesotho", "LT": "Lithuania", "LU": "Luxembourg",
    "LV": "Latvia", "LY": "Libya", "MA": "Morocco", "MC": "Monaco", "MD": "Moldova",
    "ME": "Montenegro", "MF": "Saint Martin", "MG": "Madagascar", "MH": "Marshall Islands",
    "MK": "North Macedonia", "ML": "Mali", "MM": "Myanmar", "MN": "Mongolia", "MO": "Macao",
    "MP": "Northern Mariana Islands", "MQ": "Martinique", "MR": "Mauritania", "MS": "Montserrat",
    "MT": "Malta", "MU": "Mauritius", "MV": "Maldives", "MW": "Malawi", "MX": "Mexico",
    "MY": "Malaysia", "MZ": "Mozambique", "NA": "Namibia", "NC": "New Caledonia", "NE": "Niger",
    "NF": "Norfolk Island", "NG": "Nigeria", "NI": "Nicaragua", "NL": "Netherlands", "NO": "Norway",
    "NP": "Nepal", "NR": "Nauru", "NU": "Niue", "NZ": "New Zealand", "OM": "Oman", "PA": "Panama",
    "PE": "Peru", "PF": "French Polynesia", "PG": "Papua New Guinea", "PH": "Philippines",
    "PK": "Pakistan", "PL": "Poland", "PM": "Saint Pierre and Miquelon", "PN": "Pitcairn",
    "PR": "Puerto Rico", "PS": "Palestine", "PT": "Portugal", "PW": "Palau", "PY": "Paraguay",
    "QA": "Qatar", "RE": "Réunion", "RO": "Romania", "RS": "Serbia", "RU": "Russia", "RW": "Rwanda",
    "SA": "Saudi Arabia", "SB": "Solomon Islands", "SC": "Seychelles", "SD": "Sudan", "SE": "Sweden",
    "SG": "Singapore", "SH": "Saint Helena", "SI": "Slovenia", "SJ": "Svalbard and Jan Mayen",
    "SK": "Slovakia", "SL": "Sierra Leone", "SM": "San Marino", "SN": "Senegal", "SO": "Somalia",
    "SR": "Suriname", "SS": "South Sudan", "ST": "São Tomé and Príncipe", "SV": "El Salvador",
    "SX": "Sint Maarten", "SY": "Syria", "SZ": "Eswatini", "TC": "Turks and Caicos Islands",
    "TD": "Chad", "TF": "French Southern Territories", "TG": "Togo", "TH": "Thailand",
    "TJ": "Tajikistan", "TK": "Tokelau", "TL": "Timor-Leste", "TM": "Turkmenistan", "TN": "Tunisia",
    "TO": "Tonga", "TR": "Turkey", "TT": "Trinidad and Tobago", "TV": "Tuvalu", "TW": "Taiwan",
    "TZ": "Tanzania", "UA": "Ukraine", "UG": "Uganda", "UM": "U.S. Outlying Islands",
    "US": "United States", "UY": "Uruguay", "UZ": "Uzbekistan", "VA": "Vatican City",
    "VC": "Saint Vincent and the Grenadines", "VE": "Venezuela", "VG": "British Virgin Islands",
    "VI": "U.S. Virgin Islands", "VN": "Vietnam", "VU": "Vanuatu", "WF": "Wallis and Futuna",
    "WS": "Samoa", "YE": "Yemen", "YT": "Mayotte", "ZA": "South Africa", "ZM": "Zambia", "ZW": "Zimbabwe"
}

SPECIAL_RANGES = [
    (0, 16777215, "unspecified", "Current Network (RFC 1122)"),
    (167772160, 184549375, "private", "Private Network (RFC 1918 10.0.0.0/8)"),
    (1681915904, 1681916159, "carrier", "Carrier-Grade NAT (RFC 6598 100.64.0.0/10)"),
    (2130706432, 2147483647, "loopback", "Loopback / Localhost (RFC 1122 127.0.0.0/8)"),
    (2851995648, 2852061183, "link_local", "Link-Local / APIPA (RFC 3927 169.254.0.0/16)"),
    (2886729728, 2887778303, "private", "Private Network (RFC 1918 172.16.0.0/12)"),
    (3232235520, 3232301055, "private", "Private Network (RFC 1918 192.168.0.0/16)"),
    (3758096384, 4026531839, "multicast", "Multicast (RFC 5771 224.0.0.0/4)"),
    (4026531840, 4294967295, "reserved", "Reserved / Broadcast (RFC 1112 240.0.0.0/4)"),
]


def ip_to_int(ip_str: str) -> Optional[int]:
    """Convert an IPv4 address string to a 32-bit unsigned integer using fast C socket inet_aton."""
    try:
        return struct.unpack("!I", socket.inet_aton(ip_str.strip()))[0]
    except (socket.error, ValueError, AttributeError):
        return None


def int_to_ip(ip_int: int) -> str:
    """Convert a 32-bit unsigned integer back to an IPv4 address string."""
    try:
        return socket.inet_ntoa(struct.pack("!I", ip_int))
    except (socket.error, struct.error, OverflowError):
        return "0.0.0.0"


class IPLocationEngine:
    """
    In-memory IP Geolocation & ASN Lookup Engine.
    Uses binary search over numeric IP boundaries for microsecond resolution.
    Thread-safe and lazily loaded on first access.
    """

    def __init__(self, data_dir: Path = DATA_DIR):
        self.data_dir = data_dir
        self._lock = threading.RLock()
        self._initialized = False

        self._country_ranges: List[Tuple[int, int, str]] = []
        self._country_starts: List[int] = []

        self._asn_ranges: List[Tuple[int, int, int, str]] = []
        self._asn_starts: List[int] = []

    def _ensure_loaded(self):
        """Thread-safe lazy initialization."""
        if not self._initialized:
            with self._lock:
                if not self._initialized:
                    self._load_datasets()
                    self._initialized = True

    def reload(self):
        """Force reload datasets from disk."""
        with self._lock:
            self._initialized = False
            self._ensure_loaded()

    def _load_datasets(self):
        """Load and index country and ASN CSV files."""
        country_file = self.data_dir / "country-ipv4-num.csv"
        alt_country_file = self.data_dir / "dbip-country-ipv4.csv"
        asn_file = self.data_dir / "asn-ipv4.csv"
        alt_asn_file = self.data_dir / "dbip-asn-ipv4.csv"

        country_ranges = []
        if country_file.exists():
            logger.info("Loading numeric country database from %s", country_file)
            try:
                with open(country_file, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        parts = line.split(",")
                        if len(parts) >= 3:
                            try:
                                s_int = int(parts[0])
                                e_int = int(parts[1])
                                cc = parts[2].strip().upper()
                                country_ranges.append((s_int, e_int, cc))
                            except ValueError:
                                continue
            except Exception as e:
                logger.error("Error reading country database: %s", e)

        elif alt_country_file.exists():
            logger.info("Loading dotted country database from %s", alt_country_file)
            try:
                with open(alt_country_file, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        parts = line.split(",")
                        if len(parts) >= 3:
                            s_int = ip_to_int(parts[0])
                            e_int = ip_to_int(parts[1])
                            if s_int is not None and e_int is not None:
                                cc = parts[2].strip().upper()
                                country_ranges.append((s_int, e_int, cc))
            except Exception as e:
                logger.error("Error reading alternate country database: %s", e)

        country_ranges.sort(key=lambda x: x[0])
        self._country_ranges = country_ranges
        self._country_starts = [r[0] for r in country_ranges]
        logger.info("Loaded %d country ranges for IP geolocation", len(country_ranges))

        target_asn_file = asn_file if asn_file.exists() else (alt_asn_file if alt_asn_file.exists() else None)
        asn_ranges = []
        if target_asn_file:
            logger.info("Loading ASN database from %s", target_asn_file)
            try:
                with open(target_asn_file, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        parts = line.split(",", 3)
                        if len(parts) >= 3:
                            s_int = ip_to_int(parts[0])
                            e_int = ip_to_int(parts[1])
                            if s_int is not None and e_int is not None:
                                try:
                                    asn_val = int(parts[2].strip())
                                except ValueError:
                                    asn_val = 0
                                as_name = parts[3].strip().strip('"') if len(parts) >= 4 else ""
                                asn_ranges.append((s_int, e_int, asn_val, as_name))
            except Exception as e:
                logger.error("Error reading ASN database: %s", e)

        asn_ranges.sort(key=lambda x: x[0])
        self._asn_ranges = asn_ranges
        self._asn_starts = [r[0] for r in asn_ranges]
        logger.info("Loaded %d ASN ranges for IP intelligence", len(asn_ranges))

    def _check_special_ip(self, ip_int: int) -> Optional[Tuple[str, str]]:
        """Check if an integer IP belongs to a defined private or reserved range."""
        for s_int, e_int, net_type, desc in SPECIAL_RANGES:
            if s_int <= ip_int <= e_int:
                return net_type, desc
        return None

    def lookup(self, ip_str: str, use_cache: bool = True) -> Dict[str, Any]:
        """
        Perform a full geolocation and ASN lookup for a given IP address.
        Returns a standardized dictionary.
        """
        self._ensure_loaded()
        clean_ip = ip_str.strip()

        if use_cache and check_connection():
            try:
                cached = ip_geo_cache.find_one({"ip": clean_ip})
                if cached:
                    res = dict(cached)
                    res.pop("_id", None)
                    res.pop("_tinydb_id", None)
                    res["cached"] = True
                    return res
            except Exception as e:
                logger.debug("ip_geo_cache lookup error for %s: %s", clean_ip, e)

        ip_int = ip_to_int(clean_ip)
        if ip_int is None:
            return {
                "ip": clean_ip,
                "country_code": "",
                "country_name": "",
                "asn": 0,
                "as_name": "",
                "is_private": False,
                "network_type": "invalid",
                "description": "Invalid IPv4 address format",
                "cached": False,
            }

        special = self._check_special_ip(ip_int)
        if special:
            net_type, desc = special
            result = {
                "ip": clean_ip,
                "country_code": "LAN" if net_type == "private" else "LOC",
                "country_name": "Private Network (Local LAN)" if net_type == "private" else desc,
                "asn": 0,
                "as_name": desc,
                "is_private": net_type in ("private", "loopback", "link_local"),
                "network_type": net_type,
                "description": desc,
                "cached": False,
            }
            self._save_to_cache(clean_ip, result)
            return result

        country_code = ""
        if self._country_starts:
            idx = bisect.bisect_right(self._country_starts, ip_int) - 1
            if idx >= 0:
                s_int, e_int, cc = self._country_ranges[idx]
                if s_int <= ip_int <= e_int:
                    country_code = cc

        country_name = COUNTRY_NAMES.get(country_code, country_code if country_code else "Unknown")

        asn = 0
        as_name = ""
        if self._asn_starts:
            idx = bisect.bisect_right(self._asn_starts, ip_int) - 1
            if idx >= 0:
                s_int, e_int, asn_val, name_val = self._asn_ranges[idx]
                if s_int <= ip_int <= e_int:
                    asn = asn_val
                    as_name = name_val

        result = {
            "ip": clean_ip,
            "country_code": country_code,
            "country_name": country_name,
            "asn": asn,
            "as_name": as_name,
            "is_private": False,
            "network_type": "public",
            "description": f"Public Internet ({as_name})" if as_name else "Public Internet",
            "cached": False,
        }

        self._save_to_cache(clean_ip, result)
        return result

    def _save_to_cache(self, ip_str: str, record: Dict[str, Any]):
        """Save resolved lookup record to ip_geo_cache."""
        if not check_connection():
            return
        try:
            doc = dict(record)
            doc["cached_at"] = datetime.now(timezone.utc).isoformat()
            ip_geo_cache.update_one({"ip": ip_str}, {"$set": doc}, upsert=True)
        except Exception as e:
            logger.debug("Failed caching geo lookup for %s: %s", ip_str, e)


_engine: Optional[IPLocationEngine] = None
_engine_lock = threading.Lock()


def get_engine() -> IPLocationEngine:
    """Retrieve the global IPLocationEngine singleton."""
    global _engine
    if _engine is None:
        with _engine_lock:
            if _engine is None:
                _engine = IPLocationEngine()
    return _engine


def lookup_ip(ip_str: str, use_cache: bool = True) -> Dict[str, Any]:
    """Resolve an IP address to its Country, ASN, and network metadata."""
    return get_engine().lookup(ip_str, use_cache=use_cache)


def lookup_batch(ips: List[str], use_cache: bool = True) -> Dict[str, Dict[str, Any]]:
    """Resolve a batch of IP addresses."""
    engine = get_engine()
    return {ip: engine.lookup(ip, use_cache=use_cache) for ip in ips}


def get_country(ip_str: str) -> str:
    """Return the ISO country code for an IP address or empty string."""
    return get_engine().lookup(ip_str).get("country_code", "")


def get_asn(ip_str: str) -> Dict[str, Any]:
    """Return ASN and AS Organization for an IP address."""
    info = get_engine().lookup(ip_str)
    return {"asn": info.get("asn", 0), "as_name": info.get("as_name", "")}


def is_private_ip(ip_str: str) -> bool:
    """Return True if the IP address belongs to private/LAN/loopback space."""
    return get_engine().lookup(ip_str).get("is_private", False)


def reload_databases():
    """Reload local IP databases from disk."""
    get_engine().reload()
