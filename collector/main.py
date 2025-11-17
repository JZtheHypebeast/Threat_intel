import argparse
import sys
import warnings

warnings.filterwarnings("ignore", category=Warning, module=r"urllib3.*")

from .config import logger, mute_console
from .structured import run_structured_collection
from .unstructured import run_unstructured_rss_analysis
from .unstructured_pdf import run_unstructured_pdf_analysis as _run_unstructured_pdf_analysis
from .llm_rawtext import run_llm_rawtext

run_unstructured_pdf_analysis = _run_unstructured_pdf_analysis


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--hours", type=int)
    parser.add_argument("--structured", action="store_true")
    parser.add_argument("--unstructured-rss", action="store_true")
    parser.add_argument("--unstructured-pdf", metavar="PATH")
    parser.add_argument("--no-history", action="store_true")
    parser.add_argument("-llm", "--llm", dest="llm", action="store_true")
    args = parser.parse_args()

    if not any([args.structured, args.unstructured_rss, args.unstructured_pdf, args.llm]):
        args.structured = True

    hours = args.hours or 24

    try:
        ran_any = False

        if args.structured:
            logger.info("Running structured collection")
            run_structured_collection(hours=hours, skip_history=args.no_history)
            ran_any = True

        if args.unstructured_rss:
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

        if not ran_any:
            logger.warning(
                "No mode selected; use --structured, --unstructured-rss, --unstructured-pdf PATH, or -llm."
            )

    except Exception as e:
        logger.exception(f"Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()