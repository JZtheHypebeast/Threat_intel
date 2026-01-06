# =========================
# === Standard Library ====
# =========================
import json
import logging
import os
import sys
import warnings
from datetime import datetime

try:
    from urllib3.exceptions import NotOpenSSLWarning

    warnings.filterwarnings("ignore", category=NotOpenSSLWarning)
except Exception:
    pass

warnings.filterwarnings("ignore", category=DeprecationWarning, message=r".*SWIG.*")
warnings.filterwarnings("ignore", category=DeprecationWarning, module=r"fitz.*")

# =========================
# ===== Third-Party =======
# =========================
import requests

# =========================
# ===== Module Config =====
# =========================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
RESULTS_ROOT = os.path.join(BASE_DIR, "results")
STRUCTURED_ROOT = os.path.join(RESULTS_ROOT, "cve")
UNSTRUCTURED_ROOT = os.path.join(RESULTS_ROOT, "articles")
LLM_ROOT = os.path.join(RESULTS_ROOT, "llm")
REPORTING_ROOT = os.path.join(RESULTS_ROOT, "reporting")
PDF_ROOT = os.path.join(RESULTS_ROOT, "pdf")
LLM_RAW_ROOT = os.path.join(RESULTS_ROOT, "llmrawtext")
LOGS_DIR = os.path.join(BASE_DIR, "logs")

TODAY_STAMP = datetime.now().strftime("%Y%m%d")
RUN_STAMP = datetime.now().strftime("%H%M%S")
STRUCTURED_DAY_DIR = os.path.join(STRUCTURED_ROOT, TODAY_STAMP)
UNSTRUCTURED_DAY_DIR = os.path.join(UNSTRUCTURED_ROOT, TODAY_STAMP)
LLM_DAY_DIR = os.path.join(LLM_ROOT, TODAY_STAMP)
REPORTING_DAY_DIR = os.path.join(REPORTING_ROOT, TODAY_STAMP)
PDF_DAY_DIR = os.path.join(PDF_ROOT, TODAY_STAMP)
LLM_RAW_DAY_DIR = os.path.join(LLM_RAW_ROOT, TODAY_STAMP)
STRUCTURED_RUN_DIR = os.path.join(STRUCTURED_DAY_DIR, RUN_STAMP)
UNSTRUCTURED_RUN_DIR = os.path.join(UNSTRUCTURED_DAY_DIR, RUN_STAMP)
LLM_RUN_DIR = os.path.join(LLM_DAY_DIR, RUN_STAMP)
REPORTING_RUN_DIR = os.path.join(REPORTING_DAY_DIR, RUN_STAMP)
PDF_RUN_DIR = os.path.join(PDF_DAY_DIR, RUN_STAMP)
LLM_RAW_RUN_DIR = os.path.join(LLM_RAW_DAY_DIR, RUN_STAMP)

os.makedirs(LOGS_DIR, exist_ok=True)
LOGS_DAY_DIR = os.path.join(LOGS_DIR, TODAY_STAMP)
os.makedirs(LOGS_DAY_DIR, exist_ok=True)

CONFIG = {
    "VENDORS": os.getenv("TI_VENDORS", None),
    "RSS_FEEDS": os.getenv("TI_RSS_FEEDS", None),
    "NVD_API_BASE": os.getenv(
        "TI_NVD_API_BASE", "https://services.nvd.nist.gov/rest/json/cves/2.0"
    ),
    "CISA_KEV_URL": os.getenv(
        "TI_CISA_KEV_URL",
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    ),
    "COMMUNITY_KEV_URL": os.getenv(
        "TI_COMMUNITY_KEV_URL", "https://kevin.gtfkd.com/kev"
    ),
    "OUTPUT_DIR_STRUCTURED": STRUCTURED_RUN_DIR,
    "OUTPUT_DIR_UNSTRUCTURED": UNSTRUCTURED_RUN_DIR,
    "OUTPUT_DIR_LLM": LLM_RUN_DIR,
    "OUTPUT_DIR_LLM_RAW": LLM_RAW_RUN_DIR,
    "OUTPUT_DIR_REPORTING": REPORTING_RUN_DIR,
    "OUTPUT_DIR_PDF": PDF_RUN_DIR,
    "LOG_FILE": os.path.join(LOGS_DIR, TODAY_STAMP, "threat_intel_collector.log"),
    "USER_AGENT": os.getenv(
        "TI_USER_AGENT", "ThreatIntelCollector/5.0 (+https://example.local)"
    ),
    "ENABLE_SUMMARIZATION": os.getenv("ENABLE_SUMMARIZATION", "true").lower() == "true",
    "ENABLE_SCORING": os.getenv("ENABLE_SCORING", "true").lower() == "true",
    "EXPORT_NAVIGATOR": os.getenv("EXPORT_NAVIGATOR", "false").lower() == "true",
    "ARCHIVE_TTL_DAYS": int(os.getenv("ARCHIVE_TTL_DAYS", 90)),
    "MAX_WORKERS": int(os.getenv("TI_MAX_WORKERS", 8)),
    "MIN_SENTENCE_WORDS": int(os.getenv("MIN_SENTENCE_WORDS", 5)),
    "MIN_PARAGRAPH_WORDS": int(os.getenv("MIN_PARAGRAPH_WORDS", 20)),
    "HTTP_RETRIES_TOTAL": int(os.getenv("TI_HTTP_RETRIES_TOTAL", 3)),
    "HTTP_BACKOFF_FACTOR": float(os.getenv("TI_HTTP_BACKOFF_FACTOR", 0.3)),
    "HTTP_STATUS_FORCELIST": json.loads(
        os.getenv("TI_HTTP_STATUS_FORCELIST", "[500,502,503,504]")
    ),
    "HTTP_POOL_CONNECTIONS": int(os.getenv("TI_HTTP_POOL_CONNECTIONS", 100)),
    "HTTP_POOL_MAXSIZE": int(os.getenv("TI_HTTP_POOL_MAXSIZE", 100)),
    "REQUEST_TIMEOUT": int(os.getenv("TI_REQUEST_TIMEOUT", 25)),
    "CVE_REGEX": os.getenv("TI_CVE_REGEX", r"\\bCVE-\\d{4}-\\d{4,7}\\b"),
    "HTML_PARSER": os.getenv("TI_HTML_PARSER", "html.parser"),
    "HTML_MAX_LEN": int(os.getenv("TI_HTML_MAX_LEN", 50000)),
    "HTML_STRIP_ELEMENTS": json.loads(os.getenv("TI_HTML_STRIP_ELEMENTS", "null"))
    or ["script", "style", "noscript", "header", "footer", "nav"],
    "BOILERPLATE_KEYWORDS": json.loads(os.getenv("TI_BOILERPLATE_KEYWORDS", "null"))
    or [
        "cookies",
        "privacy",
        "terms",
        "all rights reserved",
        "subscribe",
        "advert",
        "promo",
    ],
    "PDFTOTEXT_TIMEOUT": int(os.getenv("TI_PDFTOTEXT_TIMEOUT", 30)),
    "PDF_MAX_PAGES": int(os.getenv("TI_PDF_MAX_PAGES", 50)),
    "EXCERPT_RADIUS": int(os.getenv("TI_EXCERPT_RADIUS", 160)),
    "TOP_FINDING_MIN_WORDS": int(os.getenv("TI_TOP_FINDING_MIN_WORDS", 10)),
    "TOP_FINDING_MAX_WORDS": int(os.getenv("TI_TOP_FINDING_MAX_WORDS", 80)),
    "SUMMARY_MAX_SENTENCES": int(os.getenv("TI_SUMMARY_MAX_SENTENCES", 2)),
    "SUMMARY_MAX_CHARS": int(os.getenv("TI_SUMMARY_MAX_CHARS", 500)),
    "PROVENANCE_KEYWORDS": json.loads(os.getenv("TI_PROVENANCE_KEYWORDS", "null"))
    or ["chatgpt", "openai", "bard", "gemini", "copilot"],
    "PROVENANCE_STRIP_PATTERNS": json.loads(
        os.getenv("TI_PROVENANCE_STRIP_PATTERNS", "null")
    )
    or [
        "(?i)generated by chatgpt.*?$",
        "(?i)powered by openai.*?$",
        "(?i)created with bard.*?$",
        "(?i)content generated by an ai.*?$",
    ],
    "ENABLE_UA_ROTATION": os.getenv("TI_ENABLE_UA_ROTATION", "true").lower() == "true",
    "FALLBACK_USER_AGENTS": (
        json.loads(os.getenv("TI_FALLBACK_USER_AGENTS", "[]"))
        if os.getenv("TI_FALLBACK_USER_AGENTS")
        else [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.4 Safari/605.1.15",
            "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/116.0",
        ]
    ),
    "INCLUDE_ENTRIES_WITHOUT_DATE": os.getenv(
        "TI_INCLUDE_ENTRIES_WITHOUT_DATE", "true"
    ).lower()
    == "true",
    "ENABLER_KEYWORDS": (
        json.loads(os.getenv("TI_ENABLER_KEYWORDS", "[]"))
        if os.getenv("TI_ENABLER_KEYWORDS")
        else None
    ),
    "CRITICAL_THRESHOLD": float(os.getenv("TI_CRITICAL", 8.5)),
    "INTERESTING_MIN": float(os.getenv("TI_INTERESTING_MIN", 6.5)),
    "INTERESTING_MAX": float(os.getenv("TI_INTERESTING_MAX", 8.5)),
    "SIEM_ENABLED": os.getenv("TI_SIEM_ENABLED", "false").lower() == "true",
    "SIEM_TYPE": os.getenv("TI_SIEM_TYPE", "elastic"),
    "ELASTIC_ENDPOINT": os.getenv("TI_ELASTIC_ENDPOINT", "http://localhost:9200"),
    "ELASTIC_INDEX": os.getenv("TI_ELASTIC_INDEX", "threat_intel_unstructured"),
    "ELASTIC_API_KEY": os.getenv("TI_ELASTIC_API_KEY", None),
    "ELASTIC_USER": os.getenv("TI_ELASTIC_USER", None),
    "ELASTIC_PASS": os.getenv("TI_ELASTIC_PASS", None),
    "SIEM_BATCH_SIZE": int(os.getenv("TI_SIEM_BATCH_SIZE", 50)),
    "SIEM_MAX_RETRIES": int(os.getenv("TI_SIEM_MAX_RETRIES", 3)),
    "SIEM_TIMEOUT": int(os.getenv("TI_SIEM_TIMEOUT", 15)),
    "SIEM_DRY_RUN": os.getenv("TI_SIEM_DRY_RUN", "true").lower() == "true",
    "LLM_REQUEST_TIMEOUT": int(os.getenv("TI_LLM_REQUEST_TIMEOUT", 420)),
    "OLLAMA_HOST": os.getenv("TI_OLLAMA_HOST", "http://localhost:11434"),
    "LLM_MODEL": os.getenv("TI_LLM_MODEL", os.getenv("OLLAMA_MODEL", "llama3.1")),
    "LLM_ENABLED": os.getenv("TI_LLM_ENABLED", "true").lower() == "true",
    "LLM_TEMPERATURE": float(os.getenv("TI_LLM_TEMPERATURE", 0.2)),
    "EXCLUDED_SOFTWARE": json.loads(os.getenv("TI_EXCLUDED_SOFTWARE", "[]")),

# =========================
# ======= GeoFeed =========
# =========================

    "GEOFEED_ENABLED": os.getenv("TI_GEOFEED_ENABLED", "false").lower() == "true",

    "GEOFEED_MIN_SCORE": float(os.getenv("TI_GEOFEED_MIN_SCORE", 3.0)),

    "GEOFEED_MAX_ITEMS_PER_FEED": int(os.getenv("TI_GEOFEED_MAX_ITEMS_PER_FEED", 60)),
    "GEOFEED_REQUEST_TIMEOUT": int(os.getenv("TI_GEOFEED_REQUEST_TIMEOUT", 25)),

    "GEOFEED_USE_OLLAMA": os.getenv("TI_GEOFEED_USE_OLLAMA", "true").lower() == "true",
    "GEOFEED_OLLAMA_MODEL": os.getenv(
        "TI_GEOFEED_OLLAMA_MODEL",
        os.getenv("TI_LLM_MODEL", "llama3.1"),
    ),
    "GEOFEED_ADD_LLM_SUMMARY": os.getenv("TI_GEOFEED_ADD_LLM_SUMMARY", "true").lower() == "true",
    "GEOFEED_LLM_SUMMARY_MAX_CHARS": int(os.getenv("TI_GEOFEED_LLM_SUMMARY_MAX_CHARS", 280)),

    "GEOFEED_RSS_FEEDS": json.loads(os.getenv("TI_GEOFEED_RSS_FEEDS", "null"))
    or [
        # --- Google News (baseline aggregation) ---
        "https://news.google.com/rss/search?q=(Venezuela+OR+Guyana+OR+Suriname+OR+Aruba+OR+Caribbean)+(sanctions+OR+OFAC+OR+airspace+OR+NOTAM+OR+closure+OR+deployment+OR+ultimatum+OR+retaliation)+when:7d&hl=en-US&gl=US&ceid=US:en",
        "https://news.google.com/rss/search?q=(Venezuela+OR+Guyana+OR+Suriname+OR+Aruba+OR+Caribbean)+(sanctions+OR+OFAC+OR+treasury+OR+designation+OR+secondary+sanctions)+when:14d&hl=en-US&gl=US&ceid=US:en",
        "https://news.google.com/rss/search?q=(Venezuela+OR+Guyana+OR+Suriname+OR+Aruba+OR+Caribbean)+(military+OR+deployment+OR+navy+OR+air+force+OR+fighter+OR+drone+OR+intercept+OR+airspace)+when:14d&hl=en-US&gl=US&ceid=US:en",
        "https://news.google.com/rss/search?q=(Venezuela+OR+Caribbean+Sea+OR+Gulf+of+Venezuela)+(shipping+OR+tanker+OR+shadow+fleet+OR+insurance+OR+freight+OR+port)+when:14d&hl=en-US&gl=US&ceid=US:en",
        "https://news.google.com/rss/search?q=(Venezuela+OR+Caribbean)+(oil+OR+LNG+OR+refinery+OR+pipeline+OR+fuel)+(sanctions+OR+export+OR+shipping)+when:30d&hl=en-US&gl=US&ceid=US:en",
        "https://news.google.com/rss/search?q=(Venezuela+OR+Guyana+OR+Suriname+OR+Colombia+OR+Aruba+OR+%22United+States%22)+(war+OR+military+OR+escalation+OR+ultimatum+OR+retaliation)+when:7d&hl=en-US&gl=US&ceid=US:en",
        "https://news.google.com/rss/search?q=(Venezuela+OR+Guyana+OR+Suriname+OR+Colombia+OR+Aruba+OR+%22United+States%22)+(sanctions+OR+embargo+OR+asset+freeze+OR+designation+OR+secondary+sanctions)+when:14d&hl=en-US&gl=US&ceid=US:en",
        "https://news.google.com/rss/search?q=(Venezuela+OR+Guyana+OR+Suriname+OR+Colombia+OR+Aruba+OR+%22United+States%22)+(navy+OR+warship+OR+destroyer+OR+%22carrier+strike+group%22+OR+deployment+OR+military+posture)+when:14d&hl=en-US&gl=US&ceid=US:en",
        "https://news.google.com/rss/search?q=(Venezuela+OR+Guyana+OR+Suriname+OR+Colombia+OR+Aruba+OR+%22United+States%22)+(airspace+OR+NOTAM+OR+no-fly+OR+intercept+OR+fighter+OR+drone)+when:14d&hl=en-US&gl=US&ceid=US:en",
        "https://news.google.com/rss/search?q=(Guyana+OR+Venezuela)+(Essequibo+OR+Esequibo+OR+border+OR+incursion+OR+clash+OR+mobilization)+when:30d&hl=en-US&gl=US&ceid=US:en",
        "https://news.google.com/rss/search?q=(Guyana+OR+Suriname+OR+Venezuela+OR+Colombia+OR+Aruba)+(offshore+OR+oil+OR+rig+OR+platform+OR+FPSO+OR+%22Stabroek+Block%22)+(attack+OR+sabotage+OR+seized+OR+naval)+when:30d&hl=en-US&gl=US&ceid=US:en",

        # --- AIR / FLIGHT / AVIATION (military & ISR) ---
        "https://theaviationist.com/feed/",
        "https://www.flightradar24.com/blog/feed/",
        "https://www.adsbexchange.com/feed/",

        # --- MARITIME / NAVAL / SANCTIONS SHIPPING ---
        "https://news.usni.org/feed",
        "https://www.maritime-executive.com/rss",
        "https://gcaptain.com/feed/",
        "https://blog.marinetraffic.com/feed/",

        # --- LAND / GROUND / MILITARY POSTURE ---
        "https://www.understandingwar.org/rss.xml",
        "https://www.oryxspioenkop.com/feeds/posts/default",
        "https://warontherocks.com/feed/",

        # --- MULTI-DOMAIN / ESCALATION MAPS ---
        "https://liveuamap.com/rss",
        "https://liveuamap.com/en/rss/americas",
        "https://www.bellingcat.com/feed/",
        "https://www.crisis24.com/rss",
    ],

    # ---------------------------
    # IMPROVED CONFIGURABLES
    # ---------------------------

    "GEOFEED_WATCHLIST_LOCATIONS": json.loads(os.getenv("TI_GEOFEED_WATCHLIST_LOCATIONS", "null"))
    or [
        # Core focus countries
        "Venezuela", "Guyana", "Suriname", "Colombia", "Aruba", "United States",
        "USA", "U.S.",

        # Disputed area & spelling variants
        "Essequibo", "Esequibo", "Guayana Esequiba",

        # Key cities / political nodes
        "Caracas", "Maracaibo", "Puerto La Cruz", "Maturín",
        "Ciudad Guayana", "Puerto Ordaz", "San Félix",
        "Ciudad Bolívar", "Georgetown", "Paramaribo",
        "Bogota", "Cartagena", "Barranquilla",
        "Oranjestad", "San Nicolas",
        "Washington, DC", "Washington D.C.",

        # Border / region cues
        "Guyana-Venezuela border", "Colombia-Venezuela border",
        "Cuyuni", "Cuyuní", "Orinoco", "Orinoco River",
        "Bolívar (state)", "Delta Amacuro", "Anzoátegui", "Zulia",
        "Barima-Waini", "Cuyuni-Mazaruni", "Potaro-Siparuni",

        # Maritime / basin / offshore cues
        "Caribbean", "Caribbean Sea",
        "Gulf of Paria", "Atlantic Ocean",
        "Orinoco Delta",
        "Stabroek", "Stabroek Block",
        "Liza", "Payara", "Yellowtail",
        "Demerara", "Demerara River",
    ],


    "GEOFEED_WATCHLIST_ASSETS": json.loads(os.getenv("TI_GEOFEED_WATCHLIST_ASSETS", "null"))
    or [
        # Transport & nodes
        "port", "harbor", "terminal", "airport", "runway", "airfield", "air base",
        "border crossing", "checkpoint", "bridge", "highway", "rail", "river crossing",

        # Energy / critical infrastructure
        "pipeline", "refinery", "oil terminal", "gas plant", "LNG", "compressor station",
        "offshore platform", "platform", "rig", "drillship", "FPSO", "floating production",
        "subsea", "wellhead", "export terminal",

        # Security / military sites
        "naval base", "coast guard", "garrison", "barracks", "forward operating base",
        "radar", "air defense", "SAM site", "missile battery", "command center",
        "ammunition depot", "weapons depot",

        # Cyber/comm-ish (often relevant in escalation)
        "power plant", "substation", "transmission line",
        "telecom", "internet outage", "cell tower", "undersea cable",
    ],


    "GEOFEED_SIGNAL_WEIGHTS": json.loads(os.getenv("TI_GEOFEED_SIGNAL_WEIGHTS", "null"))
    or {
        # Kinetic / direct conflict
        "airstrike": 4, "missile": 4, "missile strike": 4, "rocket": 3,
        "drone strike": 3, "uav strike": 3, "shelling": 4, "artillery": 4,
        "bombing": 4, "strike package": 3,
        "shootdown": 5, "shot down": 5,
        "killed": 3, "casualties": 3,

        # Border / territorial escalation
        "incursion": 4, "border clash": 4, "border violation": 4,
        "cross-border": 4, "infiltration": 4,
        "seized territory": 5, "annexation": 5,
        "clash": 3, "skirmish": 3,

        # Maritime escalation / interdiction
        "blockade": 5, "naval blockade": 5,
        "interdiction": 4, "boarded": 4, "boarding": 4,
        "seized vessel": 5, "ship seized": 5, "detained crew": 4,
        "escort": 3, "convoy": 3,

        # Force posture / deployments
        "carrier strike group": 5,
        "aircraft carrier": 5,
        "warship": 3,
        "destroyer": 3,
        "frigate": 3,
        "submarine": 4,
        "naval deployment": 4,
        "task force": 4,
        "troop deployment": 4,
        "military buildup": 4,
        "mobilization": 4,
        "partial mobilization": 4,
        "conscription": 4,
        "call-up": 4,
        "state of emergency": 3,
        "martial law": 4,
        "curfew": 3,

        # Airspace / aviation triggers
        "airspace closed": 4,
        "airspace closure": 4,
        "notam": 3,
        "no-fly": 4,
        "intercept": 3,
        "scramble": 3,
        "violated airspace": 4,
        "air defense": 3,

        # Diplomatic crisis
        "expels diplomats": 4,
        "expelled diplomats": 4,
        "embassy closure": 4,
        "diplomatic relations severed": 5,
        "recall ambassador": 4,

        # Sanctions / economic coercion
        "sanctions": 3,
        "asset freeze": 4,
        "embargo": 4,
        "secondary sanctions": 5,
        "designation": 3,
        "sdn": 4,
        "ofac": 4,
        "general license": 3,
        "license revoked": 4,
        "waiver": 3,

        # Hybrid / gray-zone
        "sabotage": 4,
        "attack on infrastructure": 4,
        "explosion": 3,
        "mysterious explosion": 2,
        "internet shutdown": 3,
        "communications blackout": 3,
    },


    "GEOFEED_AMPLIFIERS": json.loads(os.getenv("TI_GEOFEED_AMPLIFIERS", "null"))
    or {
        # Critical infrastructure multipliers
        "port": 1, "harbor": 1, "terminal": 1,
        "airport": 1, "airfield": 1, "runway": 1,
        "pipeline": 2, "refinery": 2, "oil terminal": 2,
        "gas plant": 2, "lng": 2,
        "offshore": 1, "rig": 2, "drillship": 2, "fpso": 2,

        # Military site multipliers
        "naval base": 2, "air base": 2, "garrison": 2,
        "radar": 2, "air defense": 2, "sam": 2, "missile battery": 2,
        "ammunition depot": 2, "weapons depot": 2,

        # Human impact / urgency
        "evacuation": 2, "evacuation order": 3,
        "killed": 2, "dead": 2, "fatalities": 2,
        "casualties": 2, "injured": 1, "wounded": 1,
        "hostage": 3, "detained": 2,

        # Escalation language
        "ultimatum": 2,
        "retaliation": 2,
        "warning shot": 2,

        # Sanctions additive
        "sanctions": 1,

        # “Scale” cues
        "battalion": 2, "brigade": 2, "division": 3,
        "squadron": 2, "task force": 2, "fleet": 3,
        "carrier": 3,
    },


    "GEOFEED_DAMPENERS": json.loads(os.getenv("TI_GEOFEED_DAMPENERS", "null"))
    or {
        # Exercises / routine activity (often noisy)
        "exercise": 2, "drill": 2, "training": 2, "wargame": 2,
        "routine": 2, "scheduled": 2,

        # Low-signal content types
        "opinion": 2, "editorial": 2, "op-ed": 2,
        "analysis": 1, "explainer": 2, "background": 2,
        "interview": 2, "podcast": 3,
        "documentary": 3, "book": 3,

        # Time-based / commemorative noise
        "anniversary": 3, "memorial": 3, "history": 2,

        # Market chatter
        "stocks": 2, "markets": 2, "earnings": 3,
    },

    "GEOFEED_EXCLUDE_KEYWORDS": json.loads(os.getenv("TI_GEOFEED_EXCLUDE_KEYWORDS", "null"))
    or [
        "movie",
        "movies",
        "film",
        "films",
        "tv",
        "television",
        "series",
        "trailer",
        "box office",
        "holiday special",
        "just for fun",
        "year-end",
    ],

    "GEOFEED_PROXIMITY_WEIGHTS": json.loads(os.getenv("TI_GEOFEED_PROXIMITY_WEIGHTS", "null"))
    or {
        "aruba": 2.5,
        "oranjestad": 2.0,
        "san nicolas": 2.0,
        "caribbean": 1.5,
        "caribbean sea": 1.5,
        "gulf of venezuela": 2.0,
        "venezuela": 1.5,
        "puerto rico": 1.0,
        "curacao": 1.0,
        "bonaire": 0.8,
        "suriname": 0.8,
        "guyana": 0.8,
        "colombia": 0.6,
        "maracaibo": 1.0,
        "caracas": 0.8,
    },

    "GEOFEED_DECISION_THRESHOLDS": json.loads(os.getenv("TI_GEOFEED_DECISION_THRESHOLDS", "null"))
    or {
        "action_required_risk": ["High"],
        "prepare_risk": ["Elevated", "High"],
        "prepare_score": 6.0,
        "action_required_score": 8.0,
    },
}

if not CONFIG["VENDORS"]:
    CONFIG["VENDORS"] = [
        "Microsoft",
        "Cisco",
        "VMware",
        "Fortra",
        "Fortinet",
        "Palo Alto Networks",
        "Swift",
        "equensWorldline",
        "Giesecke+Devrient",
        "Regnology",
        "Dell",
        "HP",
        "NetApp",
        "Toshiba",
        "Canon",
        "EngageProcess",
        "AFAS",
        "Nettime solutions",
        "Decos",
        "Atlassian",
        "Mitel",
        "Zoom",
        "SurveyMonkey",
        "CaribMedia",
        "instagram",
        "facebook",
        "cloudflare",
        "microsoft 365",
        "Citrix",
        "docker",
        "microk8s",
        "canonical",
        "elastic",
        "microsoft defender",
        "darktrace",
        "Fox-IT",
        "netwrix",
        "veeam",
        "Setar",
        "qnap",
        "digicel",
        "Olympic banking",
        "qwihi",
        "Forti",
    ]

if not CONFIG["EXCLUDED_SOFTWARE"]:
    CONFIG["EXCLUDED_SOFTWARE"] = [
        "JOIN",
        "Grassroot"
    ]

if not CONFIG["RSS_FEEDS"]:
    CONFIG["RSS_FEEDS"] = [
        "https://gbhackers.com/feed/",
        "https://www.bleepingcomputer.com/feed/",
        "https://thehackernews.com/feeds/posts/default",
        "https://www.securityweek.com/feed",
        "https://advisories.ncsc.nl/rss/advisories",
        "https://filestore.fortinet.com/fortiguard/rss/ir.xml",
        "https://www.exploit-db.com/rss.xml",
        "https://www.zerodayinitiative.com/rss/upcoming/",
        "https://www.zerodayinitiative.com/rss/published/",
    ]

# =========================
# ======== Logging ========
# =========================
file_handler = logging.FileHandler(CONFIG["LOG_FILE"])
file_handler.setLevel(logging.INFO)

console_handler = logging.StreamHandler(sys.stdout)
console_handler.setLevel(logging.INFO)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[file_handler, console_handler],
)

logger = logging.getLogger("threat-collector")


def mute_console():
    console_handler.setLevel(logging.ERROR)


def unmute_console():
    console_handler.setLevel(logging.INFO)


def write_jsonl(path, records):
    with open(path, "w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    logger.info(f"Wrote {len(records)} records -> {path}")


def safe_get(d, path, default=None):
    for k in path.split("."):
        if isinstance(d, dict) and k in d:
            d = d[k]
        else:
            return default
    return d


def fetch_json(url, params=None):
    try:
        r = requests.get(
            url, headers={"User-Agent": CONFIG["USER_AGENT"]}, params=params, timeout=30
        )
        r.raise_for_status()
        return r.json()
    except Exception as e:
        logger.warning(f"Failed to fetch {url}: {e}")
        return {}
