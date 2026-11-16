"""Terminal progress bar for long scans.

    [##############--------------]  52%  Step 9/16  Reading system log: remote access
    Elapsed 04:12 · about 03:50 left

* Stages have weights (rough relative duration); a stage may report a sub-fraction
  (e.g. 3 of 7 log queries done) so the bar keeps moving inside long stages.
* Normal log lines are printed ABOVE the bar, which is redrawn underneath.
* When the output is not a terminal (CI, `--json`, piping) it prints plain one-line
  progress messages instead of redrawing.
"""

from __future__ import annotations

import shutil
import sys
import time


def _clock(sec: float) -> str:
    sec = max(0, int(sec))
    h, rem = divmod(sec, 3600)
    m, s = divmod(rem, 60)
    return f"{h:d}:{m:02d}:{s:02d}" if h else f"{m:02d}:{s:02d}"


class Progress:
    def __init__(self, stages: list, stream=None, enabled: bool = True):
        """stages: list of (key, label, weight)."""
        self.stages = [s for s in stages if s[2] > 0]
        self.total = float(sum(w for _k, _l, w in self.stages)) or 1.0
        self.stream = stream or sys.stderr
        self.enabled = enabled
        try:
            self.tty = self.stream.isatty()
        except (AttributeError, ValueError):
            self.tty = False
        self.start = time.time()
        self.idx = -1
        self.done_weight = 0.0
        self.sub = 0.0
        self.detail = ""
        self._drawn = False
        self._last_plain = -1

    # ------------------------------------------------------------ API
    def stage(self, key: str, detail: str = "") -> None:
        """Mark the stage `key` as started (all earlier stages count as done)."""
        for i, (k, _l, _w) in enumerate(self.stages):
            if k == key:
                self.done_weight = sum(w for _k, _l2, w in self.stages[:i])
                self.idx, self.sub, self.detail = i, 0.0, detail
                self.draw()
                return

    def update(self, fraction: float, detail: str = "") -> None:
        """Progress inside the current stage (0..1)."""
        self.sub = min(max(fraction, 0.0), 1.0)
        if detail:
            self.detail = detail
        self.draw()

    def finish(self, message: str = "Complete") -> None:
        self.idx, self.done_weight, self.sub, self.detail = len(self.stages) - 1, self.total, 0.0, message
        self.draw(final=True)
        if self.tty and self.enabled:
            self.stream.write("\n\n")
            self.stream.flush()
        self._drawn = False

    def log(self, *args, **kwargs) -> None:
        """Print a normal message above the bar."""
        msg = " ".join(str(a) for a in args)
        if self.enabled and self.tty and self._drawn:
            self.stream.write("\r\033[K\033[1A\r\033[K")  # clear the two bar lines
            self._drawn = False
        print(msg, file=kwargs.get("file", self.stream), flush=True)
        if self.enabled and self.tty and self.idx >= 0:
            self.draw()

    # ----------------------------------------------------------- render
    @property
    def fraction(self) -> float:
        cur = self.stages[self.idx][2] * self.sub if 0 <= self.idx < len(self.stages) else 0
        return min((self.done_weight + cur) / self.total, 1.0)

    def eta(self) -> str:
        f = self.fraction
        el = time.time() - self.start
        if f < 0.03 or el < 5:
            return "estimating..."
        return "about " + _clock(el / f - el) + " left"

    def draw(self, final: bool = False) -> None:
        if not self.enabled or self.idx < 0:
            return
        f = self.fraction
        pct = int(f * 100)
        label = self.stages[self.idx][1]
        step = f"Step {self.idx + 1}/{len(self.stages)}"
        text = f"{label}" + (f": {self.detail}" if self.detail and self.detail != label else "")
        el = _clock(time.time() - self.start)
        if not self.tty:
            if pct != self._last_plain or final:
                self._last_plain = pct
                self.stream.write(f"[{pct:3d}%] {step} {text} (elapsed {el})\n")
                self.stream.flush()
            return
        cols = shutil.get_terminal_size((80, 20)).columns
        width = max(10, min(40, cols - 30))
        filled = int(width * f)
        bar = "\033[32m" + "\u2588" * filled + "\033[0m" + "\u2591" * (width - filled)
        line1 = f" {bar} {pct:3d}%  {step}"                     # visible length ~ width + 22 < cols
        tail = f"Elapsed {el} | " + ("done" if final else self.eta())
        line2 = f"  {tail} | {text}"[: cols - 1]
        if self._drawn:
            self.stream.write("\r\033[K\033[1A\r\033[K")
        self.stream.write(f"{line1}\n{line2}")
        self.stream.flush()
        self._drawn = True
