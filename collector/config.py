import json
import logging
import os
import sys
from datetime import datetime

import requests

BASE_DIR =os .path .dirname (os .path .abspath (__file__ ))
RESULTS_ROOT =os .path .join (BASE_DIR ,"results")
LOGS_DIR =os .path .join (BASE_DIR ,"logs")

TODAY_STAMP =datetime .now ().strftime ("%Y%m%d")
RESULTS_DIR =os .path .join (RESULTS_ROOT ,TODAY_STAMP )

os .makedirs (RESULTS_DIR ,exist_ok =True )
os .makedirs (LOGS_DIR ,exist_ok =True )
# create a day-specific logs folder so logs are stored per-day
LOGS_DAY_DIR = os.path.join(LOGS_DIR, TODAY_STAMP)
os.makedirs(LOGS_DAY_DIR, exist_ok=True)

CONFIG ={
"VENDORS":os .getenv ("TI_VENDORS",None ),
"RSS_FEEDS":os .getenv ("TI_RSS_FEEDS",None ),
"NVD_API_BASE":os .getenv (
"TI_NVD_API_BASE","https://services.nvd.nist.gov/rest/json/cves/2.0"
),
"CISA_KEV_URL":os .getenv (
"TI_CISA_KEV_URL",
"https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
),
"COMMUNITY_KEV_URL":os .getenv (
"TI_COMMUNITY_KEV_URL","https://kevin.gtfkd.com/kev"
),
"OUTPUT_DIR":RESULTS_DIR ,
"LOG_FILE":os .path .join (LOGS_DIR, TODAY_STAMP, "threat_intel_collector.log"),
"USER_AGENT":os .getenv (
"TI_USER_AGENT","ThreatIntelCollector/5.0 (+https://example.local)"
),
"ENABLE_SUMMARIZATION":os .getenv ("ENABLE_SUMMARIZATION","true").lower ()=="true",
"ENABLE_SCORING":os .getenv ("ENABLE_SCORING","true").lower ()=="true",
"WEIGHT_ACTORS":int (os .getenv ("WEIGHT_ACTORS",30 )),
"WEIGHT_CAMPAIGNS":int (os .getenv ("WEIGHT_CAMPAIGNS",25 )),
"WEIGHT_THREATS":int (os .getenv ("WEIGHT_THREATS",25 )),
"WEIGHT_DENSITY":int (os .getenv ("WEIGHT_DENSITY",20 )),
"TECHNIQUE_SCORE_BOOST":json .loads (os .getenv ("TECHNIQUE_SCORE_BOOST","{}")),
"EXPORT_NAVIGATOR":os .getenv ("EXPORT_NAVIGATOR","false").lower ()=="true",
"ARCHIVE_TTL_DAYS":int (os .getenv ("ARCHIVE_TTL_DAYS",90 )),
"FUZZY_MATCHING_ENABLE":os .getenv ("FUZZY_MATCHING_ENABLE","false").lower ()
=="true",
"FUZZY_MATCH_THRESHOLD":int (os .getenv ("FUZZY_MATCH_THRESHOLD",85 )),
"MAX_WORKERS":int (os .getenv ("TI_MAX_WORKERS",8 )),
"MIN_SENTENCE_WORDS":int (os .getenv ("MIN_SENTENCE_WORDS",5 )),
"MIN_PARAGRAPH_WORDS":int (os .getenv ("MIN_PARAGRAPH_WORDS",20 )),
"MIN_REPEAT_FOR_SHORT_MATCH":int (os .getenv ("MIN_REPEAT_FOR_SHORT_MATCH",2 )),
"HTTP_RETRIES_TOTAL":int (os .getenv ("TI_HTTP_RETRIES_TOTAL",3 )),
"HTTP_BACKOFF_FACTOR":float (os .getenv ("TI_HTTP_BACKOFF_FACTOR",0.3 )),
"HTTP_STATUS_FORCELIST":json .loads (
os .getenv ("TI_HTTP_STATUS_FORCELIST","[500,502,503,504]")
),
"HTTP_POOL_CONNECTIONS":int (os .getenv ("TI_HTTP_POOL_CONNECTIONS",100 )),
"HTTP_POOL_MAXSIZE":int (os .getenv ("TI_HTTP_POOL_MAXSIZE",100 )),
"REQUEST_TIMEOUT":int (os .getenv ("TI_REQUEST_TIMEOUT",25 )),
"PATTERNS_FILE":os .getenv ("TI_PATTERNS_FILE",None ),
"MITRE_MAP_FILE":os .getenv ("TI_MITRE_MAP_FILE",None ),
"MITRE_MITIGATIONS_FILE":os .getenv ("TI_MITRE_MITIGATIONS_FILE",None ),
"CVE_REGEX":os .getenv ("TI_CVE_REGEX",r"\\bCVE-\\d{4}-\\d{4,7}\\b"),
"HTML_PARSER":os .getenv ("TI_HTML_PARSER","html.parser"),
"HTML_MAX_LEN":int (os .getenv ("TI_HTML_MAX_LEN",50000 )),
"HTML_STRIP_ELEMENTS":json .loads (os .getenv ("TI_HTML_STRIP_ELEMENTS","null"))
or ["script","style","noscript","header","footer","nav"],
"BOILERPLATE_KEYWORDS":json .loads (os .getenv ("TI_BOILERPLATE_KEYWORDS","null"))
or [
"cookies",
"privacy",
"terms",
"all rights reserved",
"subscribe",
"advert",
"promo",
],
"PDFTOTEXT_TIMEOUT":int (os .getenv ("TI_PDFTOTEXT_TIMEOUT",30 )),
"PDF_MAX_PAGES":int (os .getenv ("TI_PDF_MAX_PAGES",50 )),
"EXCERPT_RADIUS":int (os .getenv ("TI_EXCERPT_RADIUS",160 )),
"TOP_FINDING_MIN_WORDS":int (os .getenv ("TI_TOP_FINDING_MIN_WORDS",10 )),
"TOP_FINDING_MAX_WORDS":int (os .getenv ("TI_TOP_FINDING_MAX_WORDS",80 )),
"BULLET_FINDING_REGEX":os .getenv (
"TI_BULLET_FINDING_REGEX",
r"^[-*•]\s+|^\d+[.)]\s+|^(?:finding|finding\s+\d+)\s*[:\-]\s*",
),
"PROMO_PATTERNS":json .loads (os .getenv ("TI_PROMO_PATTERNS","null"))
or [
"^sign up for our newsletter",
"^follow us on\\s+",
"^related articles",
"^sponsored content",
"^about the author",
"^share\\b",
"^download now",
"^topics acquisition",
"^topics\\b",
"^(?:[A-Za-z0-9'\"\\-]{1,20}\\s+){10,}.*$",
],
"SHORT_SOCIAL_REGEX":os .getenv (
"TI_SHORT_SOCIAL_REGEX",
r"\\b(follow|subscribe|share|like|google news|gbhackers|tweet|facebook|twitter|linkedin|reddit)\\b",
),
"SHORT_SOCIAL_MAX_WORDS":int (os .getenv ("TI_SHORT_SOCIAL_MAX_WORDS",8 )),
"VENDOR_KEYWORDS":(
json .loads (os .getenv ("TI_VENDOR_KEYWORDS","[]"))
if os .getenv ("TI_VENDOR_KEYWORDS")
else None
),
"SUMMARY_MAX_SENTENCES":int (os .getenv ("TI_SUMMARY_MAX_SENTENCES",2 )),
"SUMMARY_MAX_CHARS":int (os .getenv ("TI_SUMMARY_MAX_CHARS",500 )),
"ACTIONABILITY_WEIGHTS":(
json .loads (os .getenv ("TI_ACTIONABILITY_WEIGHTS","null"))
if os .getenv ("TI_ACTIONABILITY_WEIGHTS")
else None
),
"PROVENANCE_KEYWORDS":json .loads (os .getenv ("TI_PROVENANCE_KEYWORDS","null"))
or ["chatgpt","openai","bard","gemini","copilot"],
"PROVENANCE_STRIP_PATTERNS":json .loads (
os .getenv ("TI_PROVENANCE_STRIP_PATTERNS","null")
)
or [
"(?i)generated by chatgpt.*?$",
"(?i)powered by openai.*?$",
"(?i)created with bard.*?$",
"(?i)content generated by an ai.*?$",
],
"SECTOR_KEYWORDS_MAP":(
json .loads (os .getenv ("TI_SECTOR_KEYWORDS_MAP","null"))
if os .getenv ("TI_SECTOR_KEYWORDS_MAP")
else None
),
"COMPILED_PATTERNS_CACHE_MAXSIZE":int (
os .getenv ("TI_COMPILED_PATTERNS_CACHE_MAXSIZE",1 )
),
"SURICATA_SID_START":int (os .getenv ("TI_SURICATA_SID_START",1000001 )),
"SURICATA_ALERT_TEMPLATE":os .getenv (
"TI_SURICATA_ALERT_TEMPLATE",
'alert dns any any -> any any (msg:"suspicious domain {dom}"; dns_query; content:"{dom}"; sid:{sid};)',
),
"MAX_SNIPPETS_PER_TYPE":int (os .getenv ("TI_MAX_SNIPPETS_PER_TYPE",3 )),
"MITIG_SNIPPET_FIRST_SENT_MAX":int (
os .getenv ("TI_MITIG_SNIPPET_FIRST_SENT_MAX",200 )
),
"MITIG_SNIPPET_MAX_CHARS":int (os .getenv ("TI_MITIG_SNIPPET_MAX_CHARS",300 )),
"ENABLE_UA_ROTATION":os .getenv ("TI_ENABLE_UA_ROTATION","true").lower ()=="true",
"FALLBACK_USER_AGENTS":(
json .loads (os .getenv ("TI_FALLBACK_USER_AGENTS","[]"))
if os .getenv ("TI_FALLBACK_USER_AGENTS")
else [
"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36",
"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.4 Safari/605.1.15",
"Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/116.0",
]
),
"INCLUDE_ENTRIES_WITHOUT_DATE":os .getenv (
"TI_INCLUDE_ENTRIES_WITHOUT_DATE","true"
).lower ()
=="true",
"ENABLER_KEYWORDS":(
json .loads (os .getenv ("TI_ENABLER_KEYWORDS","[]"))
if os .getenv ("TI_ENABLER_KEYWORDS")
else None
),
"CRITICAL_THRESHOLD":float (os .getenv ("TI_CRITICAL",8.5 )),
"INTERESTING_MIN":float (os .getenv ("TI_INTERESTING_MIN",6.5 )),
"INTERESTING_MAX":float (os .getenv ("TI_INTERESTING_MAX",8.5 )),
"SIEM_ENABLED":os .getenv ("TI_SIEM_ENABLED","false").lower ()=="true",
"SIEM_TYPE":os .getenv ("TI_SIEM_TYPE","elastic"),
"ELASTIC_ENDPOINT":os .getenv ("TI_ELASTIC_ENDPOINT","http://localhost:9200"),
"ELASTIC_INDEX":os .getenv ("TI_ELASTIC_INDEX","threat_intel_unstructured"),
"ELASTIC_API_KEY":os .getenv ("TI_ELASTIC_API_KEY",None ),
"ELASTIC_USER":os .getenv ("TI_ELASTIC_USER",None ),
"ELASTIC_PASS":os .getenv ("TI_ELASTIC_PASS",None ),
"SIEM_BATCH_SIZE":int (os .getenv ("TI_SIEM_BATCH_SIZE",50 )),
"SIEM_MAX_RETRIES":int (os .getenv ("TI_SIEM_MAX_RETRIES",3 )),
"SIEM_TIMEOUT":int (os .getenv ("TI_SIEM_TIMEOUT",15 )),
"SIEM_DRY_RUN":os .getenv ("TI_SIEM_DRY_RUN","true").lower ()=="true",
"MITRE_PRIORITY_BASE_WEIGHT":float (
os .getenv ("TI_MITRE_PRIORITY_BASE_WEIGHT",0.6 )
),
"MITRE_PRIORITY_EVIDENCE_WEIGHT":float (
os .getenv ("TI_MITRE_PRIORITY_EVIDENCE_WEIGHT",0.4 )
),
"INFERRED_TECHNIQUE_SCORE_MULTIPLIER":float (
os .getenv ("TI_INFERRED_TECHNIQUE_SCORE_MULTIPLIER",0.8 )
),
"MITRE_SIGNAL_MENTION":int (os .getenv ("TI_MITRE_SIGNAL_MENTION",30 )),
"MITRE_SIGNAL_CVE":int (os .getenv ("TI_MITRE_SIGNAL_CVE",20 )),
"MITRE_SIGNAL_IOC":int (os .getenv ("TI_MITRE_SIGNAL_IOC",15 )),
"MITRE_SIGNAL_ACTIONABILITY":int (os .getenv ("TI_MITRE_SIGNAL_ACTIONABILITY",25 )),
}

if not CONFIG ["VENDORS"]:
    CONFIG ["VENDORS"]=[
    "Microsoft",
    "Cisco",
    "VMware",
    "Fortinet",
    "Palo Alto Networks",
    "Palo Alto",
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
    "JOIN",
    "Jira",
    "GoAnywhere",
    "Mitel",
    "Teams",
    "Zoom",
    "SurveyMonkey",
    "CaribMedia",
    "instagram",
    "facebook",
    "canva",
    "cloudflare",
    "microsoft 365",
    "Citrix",
    "docker",
    "Kubernetes",
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

if not CONFIG ["RSS_FEEDS"]:
    CONFIG ["RSS_FEEDS"]=[
    "https://gbhackers.com/feed/",
    "https://www.bleepingcomputer.com/feed/",
    "https://thehackernews.com/feeds/posts/default",
    "https://www.securityweek.com/feed",
    "https://advisories.ncsc.nl/rss/advisories",
    "https://filestore.fortinet.com/fortiguard/rss/ir.xml",
    ]

if not CONFIG .get ("ENABLER_KEYWORDS"):
    CONFIG ["ENABLER_KEYWORDS"]=[
    "ai",
    "artificial intelligence",
    "machine learning",
    "third-party",
    "outsourcing",
    "zero-day",
    "zero day",
    "unpatched",
    "cryptocurrency",
    "quantum",
    "geopolitical",
    "open-source",
    "cloud",
    "s3",
    "aws",
    "mfa",
    "phishing",
    ]

file_handler =logging .FileHandler (CONFIG ["LOG_FILE"])
file_handler .setLevel (logging .INFO )

console_handler =logging .StreamHandler (sys .stdout )
console_handler .setLevel (logging .INFO )

logging .basicConfig (
level =logging .INFO ,
format ="%(asctime)s [%(levelname)s] %(message)s",
handlers =[file_handler ,console_handler ],
)

logger =logging .getLogger ("threat-collector")

def mute_console ():
    console_handler .setLevel (logging .ERROR )

def write_jsonl (path ,records ):
    with open (path ,"w",encoding ="utf-8")as f :
        for r in records :
            f .write (json .dumps (r ,ensure_ascii =False )+"\n")
    logger .info (f"Wrote {len(records)} records -> {path}")

def safe_get (d ,path ,default =None ):
    for k in path .split ("."):
        if isinstance (d ,dict )and k in d :
            d =d [k ]
        else :
            return default
    return d

def fetch_json (url ,params =None ):
    try :
        r =requests .get (
        url ,headers ={"User-Agent":CONFIG ["USER_AGENT"]},params =params ,timeout =30
        )
        r .raise_for_status ()
        return r .json ()
    except Exception as e :
        logger .warning (f"Failed to fetch {url}: {e}")
        return {}

def load_enabler_keywords ()->list :
    kws =CONFIG .get ("ENABLER_KEYWORDS")
    if kws :
        return kws
    return [
    "ai",
    "artificial intelligence",
    "machine learning",
    "third-party",
    "outsourcing",
    "zero-day",
    "zero day",
    "unpatched",
    "cryptocurrency",
    "quantum",
    "geopolitical",
    "open-source",
    "cloud",
    "s3",
    "aws",
    "mfa",
    "phishing",
    ]
