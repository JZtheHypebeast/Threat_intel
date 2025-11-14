import argparse
import sys
import warnings
from datetime import datetime

warnings.filterwarnings("ignore", category=Warning, module=r"urllib3.*")

from .config import logger, mute_console
from .structured import run_structured_collection
from .unstructured import run_unstructured_rss_analysis
from .unstructured_pdf import (
    run_unstructured_pdf_analysis as _run_unstructured_pdf_analysis,
)

run_unstructured_pdf_analysis = _run_unstructured_pdf_analysis
import os


def main():
    parser = argparse.ArgumentParser(description="Unified Threat Intel Collector")
    parser.add_argument("--hours", type=int, help="Time window in hours (default: 24)")
    parser.add_argument(
        "--structured",
        action="store_true",
        help="Run structured collector (default if no mode flags)",
    )
    parser.add_argument(
        "--unstructured-rss", action="store_true", help="Run unstructured RSS collector"
    )
    parser.add_argument(
        "--unstructured-pdf",
        metavar="PATH",
        help="Run unstructured PDF collector on file or directory",
    )
    parser.add_argument(
        "--no-history",
        action="store_true",
        help="(Reserved) Skip change history (compat flag)",
    )
    args = parser.parse_args()

    hours = args.hours if args.hours is not None else 24
    ran_any = False

    try:
        from urllib3.exceptions import NotOpenSSLWarning

        warnings.filterwarnings("ignore", category=NotOpenSSLWarning)
    except Exception:
        pass
    mute_console()
    try:
        if args.structured or (not args.unstructured_rss and not args.unstructured_pdf):
            logger.info(f"Running STRUCTURED (last {hours}h)...")
            res_struct = run_structured_collection(hours, skip_history=args.no_history)
            logger.info(f"[Structured] Done: {res_struct}")
            try:
                date_tag = datetime.now().strftime("%Y%m%d")
                nd = f"StructuredCVEData_{date_tag}.ndjson"
                md = f"StructuredCVEReport_{date_tag}.md"
                print(
                    f"Structured: done — records={res_struct.get('records_total', 0)} new={res_struct.get('new',0)} modified={res_struct.get('modified',0)} ndjson={nd} md={md}"
                )
            except Exception:
                pass
            ran_any = True

        if args.unstructured_rss:
            logger.info(f"Running UNSTRUCTURED-RSS (last {hours}h)...")
            res_urss = run_unstructured_rss_analysis(hours)
            logger.info(f"[Unstructured RSS] Done: {res_urss}")
            try:
                nd = res_urss.get("ndjson") or ""
                md = res_urss.get("markdown") or ""
                print(
                    f"Unstructured RSS: done — records={len(res_urss.get('records', []))} ndjson={__import__('os').path.basename(nd)} md={__import__('os').path.basename(md)}"
                )
            except Exception:
                pass
            ran_any = True

        if args.unstructured_pdf:
            logger.info("Running UNSTRUCTURED-PDF...")
            path = args.unstructured_pdf
            paths = []
            if os.path.isdir(path):
                for root, _, files in os.walk(path):
                    for f in files:
                        if f.lower().endswith(".pdf"):
                            paths.append(os.path.join(root, f))
            else:
                paths = [path]

            res_updf = _run_unstructured_pdf_analysis(paths)
            logger.info(f"[Unstructured PDF] Done: {res_updf}")
            try:
                nd = res_updf.get("ndjson") or ""
                md = res_updf.get("markdown") or ""
                print(
                    f"Unstructured PDF: done — records={len(res_updf.get('records', []))} ndjson={__import__('os').path.basename(nd)} md={__import__('os').path.basename(md)}"
                )
            except Exception:
                pass
            ran_any = True

        if not ran_any:
            logger.warning(
                "No mode selected; use --structured, --unstructured-rss, or --unstructured-pdf PATH."
            )

    except Exception as e:
        logger.exception(f"Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
