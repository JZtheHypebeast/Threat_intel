import argparse
import sys
import warnings
import subprocess
import os

warnings.filterwarnings("ignore", category=Warning, module=r"urllib3.*")

from .config import logger, mute_console
from .structured import run_structured_collection
from .unstructured import run_unstructured_rss_analysis
from .unstructured_pdf import (
    run_unstructured_pdf_analysis as _run_unstructured_pdf_analysis,
)
from .llm_rawtext import run_llm_rawtext

run_unstructured_pdf_analysis = _run_unstructured_pdf_analysis


def _print_banner() -> None:
    banner = r"""
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
    logger.info(banner)


def _print_menu(current_hours: int) -> None:
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
|-- structured       :: Run structured collection
|-- unstructured     :: Run unstructured RSS analysis
|-- pdf <PATH>       :: Run unstructured PDF analysis on PATH
|-- llm              :: Run LLM rawtext translation
|-- tests            :: Run unit tests
|-- all              :: Run structured + unstructured + llm
--------------------------------------------------------------
"""
    logger.info(menu)


def _interactive_loop(default_hours: int, skip_history: bool) -> None:
    hours = default_hours
    while True:
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

        elif key == "structured":
            logger.info("Running structured collection")
            run_structured_collection(hours=hours, skip_history=skip_history)

        elif key == "unstructured":
            logger.info("Running unstructured RSS analysis")
            run_unstructured_rss_analysis(hours=hours)

        elif key == "pdf":
            path = None
            if len(parts) > 1:
                path = " ".join(parts[1:])
            else:
                path = input("PDF file or directory path: ").strip()
            if path:
                logger.info("Running unstructured PDF analysis on %s", path)
                mute_console()
                run_unstructured_pdf_analysis(path=path, hours=hours)
            else:
                logger.warning("No path specified for PDF analysis")

        elif key == "llm":
            logger.info("Running LLM rawtext translation")
            run_llm_rawtext(hours=hours)

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
            logger.info("Running structured collection")
            run_structured_collection(hours=hours, skip_history=skip_history)
            logger.info("Running unstructured RSS analysis")
            run_unstructured_rss_analysis(hours=hours)
            logger.info("Running LLM rawtext translation")
            run_llm_rawtext(hours=hours)

        else:
            logger.warning("Unknown command: %s", cmd)


def main() -> None:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--no-banner", action="store_true")
    parser.add_argument("--hours", type=int)
    parser.add_argument("--tests", action="store_true")
    parser.add_argument("--structured", action="store_true")
    parser.add_argument("--unstructured", action="store_true")
    parser.add_argument("--unstructured-pdf")
    parser.add_argument("--llm", action="store_true")
    parser.add_argument("--no-history", action="store_true")
    parser.add_argument("-h", "--help", dest="show_help", action="store_true")
    args = parser.parse_args()

    no_banner_env = os.getenv("COLLECTOR_NO_BANNER", "").lower() in ("1", "true", "yes")
    if not (getattr(args, "no_banner", False) or no_banner_env):
        _print_banner()

    hours = args.hours or 24
    skip_history = args.no_history

    try:
        if args.show_help:
            _print_menu(hours)
            sys.exit(0)

        if args.structured or args.unstructured or args.unstructured_pdf or args.llm:
            ran_any = False

            if args.structured:
                logger.info("Running structured collection")
                run_structured_collection(hours=hours, skip_history=skip_history)
                ran_any = True

            if args.unstructured:
                logger.info("Running unstructured RSS analysis")
                run_unstructured_rss_analysis(hours=hours)
                ran_any = True

            if args.unstructured_pdf:
                logger.info("Running unstructured PDF analysis")
                mute_console()
                run_unstructured_pdf_analysis(path=args.unstructured_pdf, hours=hours)
                ran_any = True

            if args.llm:
                logger.info("Running LLM rawtext translation")
                run_llm_rawtext(hours=hours)
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
                    "No mode selected; use --structured, --unstructured, --unstructured-pdf PATH, or --llm."
                )
        else:
            _interactive_loop(hours, skip_history)

    except Exception as e:
        logger.exception(f"Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
