from __future__ import annotations

# =========================
# === Standard Library ====
# =========================
import argparse
import importlib.util
import os
import subprocess
import sys
import warnings

# =========================
# ====== Local App ========
# =========================
warnings.filterwarnings("ignore", category=Warning, module=r"urllib3.*")
from .config import logger, mute_console, unmute_console
from .CVE import run_structured_collection
from .pdf import run_pdf_analysis as _run_unstructured_pdf_analysis
from .articles import run_fetch, run_llm_rawtext
from .reporting import run_reporting

run_unstructured_pdf_analysis = _run_unstructured_pdf_analysis

# =========================
# ===== Module Config =====
# =========================
DEFAULT_HOURS = 24
BANNER = r"""
/==================================================================\
||  ____           _             _        ____              _     ||
|| / ___|___ _ __ | |_ _ __ __ _| | ___  | __ )  __ _ _ __ | | __ ||
||| |   / _ \ '_ \| __| '__/ _` | |/ _ \ |  _ \ / _` | '_ \| |/ / ||
||| |__|  __/ | | | |_| | | (_| | |  __/ | |_) | (_| | | | |   <  ||
|| \____\___|_| |_|\__|_|_ \__,_|_|\___| |____/ \__,_|_| |_|_|\_\ ||
||__   ____ _ _ __      / \   _ __ _   _| |__   __ _              ||
||\ \ / / _` | '_ \    / _ \ | '__| | | | '_ \ / _` |             ||
|| \ V / (_| | | | |  / ___ \| |  | |_| | |_) | (_| |             ||
||  \_/ \__,_|_| |_| /_/   \_\_|   \__,_|_.__/ \__,_|             ||
\==================================================================/
Threat Intel Collector — Created by Marc R. Kock
"""

# =========================
# ======= Helpers =========
# =========================
def _print_banner() -> None:
    logger.info(BANNER)

def _print_menu(current_hours: int) -> None:
    geofeed_line = ""
    if _has_geofeed():
        geofeed_line = "|-- geofeed          :: Run GeoFeed geopolitical scanner (LLM summary if enabled)\n"

    menu = f"""
--------------------------------------------------------------
Threat Intel Collector Menu
--------------------------------------------------------------
Help:
|-- exit, quit, q    :: Exit collector
|-- help             :: Show this help
|-- hours <N>        :: Set time window in hours,
                        can also be used behind modules
                        (current: {current_hours})

Modules:
|-- cve              :: Run structured CVE/KEV collection
|-- articles         :: Fetch RSS articles + run LLM enrichment
{geofeed_line}|-- reporting        :: Build cumulative LLM-based report (2/7/14/30 days)
|-- tests            :: Run unit tests
|-- pdf              :: Run PDF extraction/enrichment on data/PDF folder
|-- all              :: Run CVE + articles
--------------------------------------------------------------
"""
    print(menu)

def _prompt_hours(current_hours: int) -> int:
    prompt = f"Hours to look back (press Enter for default {current_hours}h): "
    try:
        raw = input(prompt).strip()
    except EOFError:
        return current_hours
    if not raw:
        return current_hours
    try:
        chosen = int(raw)
        logger.info("Using %s hours for this run", chosen)
        return chosen
    except ValueError:
        logger.warning("Invalid hours value: %s (keeping %s)", raw, current_hours)
        return current_hours


def _prompt_reporting_period() -> int:
    prompt = (
        "Reporting window (days): choose 2, 7, 14, or 30 (press Enter for 7): "
    )
    try:
        raw = input(prompt).strip()
    except EOFError:
        return 7
    if not raw:
        return 7
    try:
        chosen = int(raw)
        if chosen in (2, 7, 14, 30):
            return chosen
    except ValueError:
        pass
    logger.warning("Invalid selection; defaulting to 7 days")
    return 7


def _has_geofeed() -> bool:
    pkg = __package__ or ""
    mod = f"{pkg}.geofeed" if pkg else "geofeed"
    return importlib.util.find_spec(mod) is not None


def _run_geofeed(hours: int) -> None:
    pkg = __package__ or ""
    mod = f"{pkg}.geofeed" if pkg else "geofeed"
    if importlib.util.find_spec(mod) is None:
        logger.warning("GeoFeed module not found (geofeed.py missing); skipping")
        return
    logger.info("Launching GeoFeed (standalone module)")
    subprocess.run([sys.executable, "-m", mod, "--hours", str(hours)], check=False)

# =========================
# ======= Runner ==========
# =========================
def _interactive_loop(default_hours: int, skip_history: bool) -> None:
    hours = default_hours
    while True:
        unmute_console()
        _print_menu(hours)
        try:
            cmd = input(">> ").strip()
        except EOFError:
            break
        if not cmd:
            continue
        parts = cmd.split()
        key = parts[0].lower()

        if key in ("exit", "quit", "q"):
            break

        elif key == "help":
            _print_menu(hours)
            continue

        elif key == "hours":
            if len(parts) > 1:
                try:
                    hours = int(parts[1])
                    logger.info("Hours set to %s", hours)
                except ValueError:
                    logger.warning("Invalid hours value: %s", parts[1])
            else:
                logger.info("Current hours: %s", hours)

        elif key == "cve":
            logger.info("Running structured collection")
            chosen_hours = _prompt_hours(hours)
            run_structured_collection(hours=chosen_hours, skip_history=skip_history)

        elif key == "pdf":
            logger.info("Running unstructured PDF analysis (data/PDF folder)")
            mute_console()
            try:
                run_unstructured_pdf_analysis()
            finally:
                unmute_console()

        elif key == "articles":
            logger.info("Running LLM rawtext translation")
            chosen_hours = _prompt_hours(hours)
            logger.info("Fetching articles to refresh rawtext before LLM")
            run_fetch(hours=chosen_hours)
            run_llm_rawtext(hours=chosen_hours)

        elif key == "geofeed":
            chosen_hours = _prompt_hours(hours)
            _run_geofeed(chosen_hours)

        elif key == "reporting":
            logger.info("Building cumulative LLM-based report")
            days = _prompt_reporting_period()
            run_reporting(period_days=days)

        elif key == "tests":
            logger.info("Running unit tests")
            try:
                rc = subprocess.run(
                    [sys.executable, "-m", "pytest", "-q", "tests"]
                ).returncode
                if rc != 0:
                    logger.warning("Unit tests finished with exit code %s", rc)
                else:
                    logger.info("Unit tests passed")
            except FileNotFoundError:
                logger.exception("pytest not found; install with 'pip install pytest'")

        elif key == "all":
            chosen_hours = _prompt_hours(hours)
            logger.info("Running structured collection")
            run_structured_collection(hours=chosen_hours, skip_history=skip_history)
            logger.info("Running article fetch + LLM enrichment")
            run_fetch(hours=chosen_hours)
            logger.info("Running LLM rawtext translation")
            run_llm_rawtext(hours=chosen_hours)

        else:
            logger.warning("Unknown command: %s", cmd)


def main() -> None:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--no-banner", action="store_true")
    parser.add_argument("--hours", type=int)
    parser.add_argument("--tests", action="store_true")
    parser.add_argument("--cve", action="store_true")
    parser.add_argument("--unstructured-pdf")
    parser.add_argument("--articles", action="store_true")
    parser.add_argument("--geofeed", action="store_true", help="Run GeoFeed geopolitical local-news scanner (if present)")
    parser.add_argument("--reporting", type=int, help="Build cumulative report over N days (2/7/14/30)")
    parser.add_argument("--no-history", action="store_true")
    parser.add_argument("-h", "--help", dest="show_help", action="store_true")
    args = parser.parse_args()

    no_banner_env = os.getenv("COLLECTOR_NO_BANNER", "").lower() in ("1", "true", "yes")
    if not (getattr(args, "no_banner", False) or no_banner_env):
        _print_banner()
    unmute_console()

    hours = args.hours or DEFAULT_HOURS
    skip_history = args.no_history

    try:
        if args.show_help:
            _print_menu(hours)
            sys.exit(0)

        if (
            args.cve
            or args.unstructured_pdf
            or args.articles
            or args.reporting
        ):
            ran_any = False

            if args.cve:
                logger.info("Running structured collection")
                run_structured_collection(hours=hours, skip_history=skip_history)
                ran_any = True

            if args.unstructured_pdf:
                logger.info("Running unstructured PDF analysis")
                mute_console()
                try:
                    run_unstructured_pdf_analysis(path=args.unstructured_pdf, hours=hours)
                finally:
                    unmute_console()
                ran_any = True

            if args.articles:
                logger.info("Running LLM rawtext translation")
                run_fetch(hours=hours)
                run_llm_rawtext(hours=hours)
                ran_any = True

            if args.geofeed:
                _run_geofeed(hours)
                ran_any = True

            if args.reporting:
                days = args.reporting
                if days not in (2, 7, 14, 30):
                    logger.warning("Invalid reporting days %s; use 2,7,14,30", days)
                else:
                    logger.info("Building cumulative LLM-based report over %s days", days)
                    run_reporting(period_days=days)
                    ran_any = True

            if args.tests:
                logger.info("Running unit tests")
                try:
                    rc = subprocess.run(
                        [sys.executable, "-m", "pytest", "-q", "tests"]
                    ).returncode
                    if rc != 0:
                        logger.warning("Unit tests finished with exit code %s", rc)
                    else:
                        logger.info("Unit tests passed")
                except FileNotFoundError:
                    logger.exception(
                        "pytest not found; install with 'pip install pytest'"
                    )
                ran_any = True

            if not ran_any:
                logger.warning(
                    "No mode selected; use --cve, --unstructured-pdf PATH, or --articles."
                )
        else:
            _interactive_loop(hours, skip_history)

    except Exception as e:
        logger.exception(f"Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
