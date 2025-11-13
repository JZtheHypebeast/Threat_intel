import shutil
import sys
import time
from typing import Optional
import threading

# =============================================================================
#                                 PROGRESS
# =============================================================================
# Small utilities for console progress display (progress bar and spinner).
# =============================================================================

def _terminal_width(default=80) -> int:
    try:
        cols = shutil.get_terminal_size().columns
        return cols if cols and cols > 20 else default
    except Exception:
        return default


def progress_bar(
    current: int,
    total: int,
    prefix: str = "",
    length: int = None,
    fill: str = "#",
    status: Optional[str] = None,
):
    if length is None:
        width = _terminal_width()
        length = max(10, min(60, width - 30))

    try:
        total_val = int(total) if total is not None else 0
    except Exception:
        total_val = 0

    if total_val <= 0:
        ratio = 1.0
    else:
        ratio = float(current) / float(total_val)
        ratio = max(0.0, min(1.0, ratio))

    percent = ratio * 100.0
    filled = int(round(length * ratio))
    filled = max(0, min(length, filled))
    bar = fill * filled + "-" * (length - filled)

    out = f"\r{prefix} [{bar}] {percent:3.0f}%"
    if status:
        out = out + " " + status
    try:
        pad_len = max(0, _terminal_width() - len(out) - 1)
        out += " " * pad_len
    except Exception:
        pass

    sys.stdout.write(out)
    sys.stdout.flush()

    if ratio >= 1.0:
        sys.stdout.write("\n")
        sys.stdout.flush()


def animate_progress(prefix: str, steps: int = 20, delay: float = 0.05):
    for i in range(steps + 1):
        progress_bar(i, steps, prefix)
        time.sleep(delay)


def start_live_progress(prefix: str, total: int, shared: dict, delay: float = 0.08):
    stop_event = threading.Event()

    def _runner():
        while not stop_event.is_set():
            try:
                cur = int(shared.get("current", 0) or 0)
            except Exception:
                cur = 0
            status = shared.get("status")
            try:
                progress_bar(cur, total, prefix=prefix, status=status)
            except Exception:
                pass
            time.sleep(delay)

        try:
            final = int(shared.get("current", 0) or 0)
            final = min(total, final)
            progress_bar(
                final if total else 1,
                total if total else 1,
                prefix=prefix,
                status=shared.get("status"),
            )
        except Exception:
            pass

    t = threading.Thread(target=_runner, daemon=True)
    t.start()
    return stop_event, t


def stop_live_progress(
    stop_event: threading.Event, thread: threading.Thread, wait: bool = True
):
    try:
        stop_event.set()
    except Exception:
        pass
    if wait:
        try:
            thread.join(timeout=2.0)
        except Exception:
            pass
