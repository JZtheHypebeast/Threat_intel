# =========================
# === Standard Library ====
# =========================
import os
import shutil
import sys
import threading
import time
from typing import Optional

# =========================
# ===== Module Config =====
# =========================
TERMINAL_WIDTH_DEFAULT = 80
PROGRESS_MIN_LEN = 10
PROGRESS_MAX_LEN = 60
INLINE_CLEAR = "\x1b[K"
DEFAULT_ANIMATE_DELAY = 0.05
DEFAULT_LIVE_DELAY = 0.08


# =========================
# ======== Helpers ========
# =========================
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
        width = _terminal_width(TERMINAL_WIDTH_DEFAULT)
        length = max(PROGRESS_MIN_LEN, min(PROGRESS_MAX_LEN, width - 30))

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

    out_no_cr = f"{prefix} [{bar}] {percent:3.0f}%"
    if status:
        out_no_cr = out_no_cr + " " + status

    try:
        disable_inline = os.getenv("TI_DISABLE_INLINE", "false").lower() == "true"
    except Exception:
        disable_inline = False

    prefer_inline = not disable_inline

    if prefer_inline:
        out_stream = sys.stderr if getattr(sys, "stderr", None) else sys.stdout
        try:
            if hasattr(sys, "__stdout__") and sys.stdout is not sys.__stdout__:
                out_stream = sys.stdout
        except Exception:
            pass

        if not hasattr(progress_bar, "_lock"):
            try:
                import threading as _threading

                progress_bar._lock = _threading.Lock()
            except Exception:
                progress_bar._lock = None
        lock = getattr(progress_bar, "_lock", None)

        to_write = "\r" + out_no_cr + INLINE_CLEAR
        try:
            if lock:
                lock.acquire()

            last_str = getattr(progress_bar, "_last_str", None)
            if last_str == out_no_cr:

                return
            out_stream.write(to_write)
            out_stream.flush()
            progress_bar._last_len = len(out_no_cr)
            progress_bar._last_str = out_no_cr
        except Exception:
            pass
        finally:
            try:
                if lock:
                    lock.release()
            except Exception:
                pass

        if ratio >= 1.0:
            try:
                out_stream.write("\n")
                out_stream.flush()
            except Exception:
                pass
            progress_bar._last_len = 0
    else:

        try:
            sys.stdout.write(out_no_cr + "\n")
            sys.stdout.flush()
        except Exception:
            pass


def animate_progress(prefix: str, steps: int = 20, delay: float = 0.05):
    for i in range(steps + 1):
        progress_bar(i, steps, prefix)
        time.sleep(delay or DEFAULT_ANIMATE_DELAY)


def start_live_progress(
    prefix: str, total: int, shared: dict, delay: float = DEFAULT_LIVE_DELAY
):
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
