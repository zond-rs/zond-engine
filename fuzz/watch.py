#!/usr/bin/env python3
"""Renders a libFuzzer run as a status screen instead of a scroll.

    cargo +nightly fuzz run import_nmap fuzz/corpus/import_nmap \
        fuzz/seeds/import_nmap -- -dict=... 2>&1 | python3 fuzz/watch.py import_nmap

libFuzzer has no status screen and no periodic-summary mode: it prints a line
per event and that is the whole of its interface. This reads that stream and
draws the numbers in place.

The reason it exists rather than being a nicer colour scheme is the last line of
the block. **libFuzzer never says how long it has been since it found
anything**, and that is the number a campaign is steered by: a target that has
gone an hour without new coverage is a target to stop and swap out. Working it
out from the scroll means reading timestamps that are not there.

A crash is never rendered. On the first sign of one this drops out of the way
and passes everything through, because a status screen that swallowed the report
would be worse than the scroll it replaced.

`--json <path>` writes the same numbers somewhere a program can read them. The
screen is drawn only for a terminal, so a run whose output is being collected
costs nothing to render.
"""

import json
import os
import re
import sys
import time

# Every libFuzzer stats line carries these, in an order that has changed between
# releases, so each is found by name rather than by position.
FIELDS = {
    "cov": re.compile(r"\bcov: (\d+)"),
    "ft": re.compile(r"\bft: (\d+)"),
    "corp": re.compile(r"\bcorp: (\d+)/(\d+)([KMG]?)b"),
    "exec_s": re.compile(r"\bexec/s: (\d+)"),
    "rss": re.compile(r"\brss: (\d+)Mb"),
    "execs": re.compile(r"^#(\d+)"),
}

# The word after the execution count: NEW, REDUCE, pulse, INITED, DONE. Matched
# on any whitespace, because libFuzzer separates it with a tab and looking for a
# space finds nothing — which reads on the screen as a target that has never
# found anything while its corpus grows in front of you.
EVENT = re.compile(r"^#\d+\s+(\w+)")

# What libFuzzer says when it is no longer fuzzing.
#
# **Anchored, and case-sensitive.** A loose pattern matching `ERROR` anywhere in
# a line would match a word that turns up in ordinary output: libFuzzer prints
# `NEW_FUNC[1/1]: 0x... in <mangled symbol>` whenever it reaches a new function,
# and a Rust symbol for anything touching `serde_json::error::Error` carries it.
# Every import target would hit one within seconds of starting and the screen
# would never be drawn again.
#
# The banners below all begin a line, so anchoring is what separates them from a
# symbol name. `panicked at` needs no anchor: a mangled symbol has no spaces in
# it.
TROUBLE = re.compile(
    r"""
      ^==\d+==\s*ERROR:      # the sanitizer and libFuzzer crash banner
    | ^ERROR:                # libFuzzer's own, and its startup refusals
    | ^SUMMARY:              # what a sanitizer prints after one
    | ^Test\ unit\ written   # the artifact reached the disk
    | panicked\ at           # a Rust panic, wherever it appears
    """,
    re.VERBOSE,
)

# What libFuzzer's `corp:` suffix means, so the size is available as a number
# and not only as the string the screen prints.
SCALE = {"": 1, "K": 1024, "M": 1024**2, "G": 1024**3}

CLEAR = "\033[H\033[J"
DIM = "\033[2m"
BOLD = "\033[1m"
OFF = "\033[0m"


def elapsed(seconds):
    """A duration as a person reads one."""
    seconds = int(seconds)
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m {seconds % 60:02d}s"
    return f"{seconds // 3600}h {(seconds % 3600) // 60:02d}m"


def thousands(value):
    return f"{value:,}".replace(",", " ")


class Screen:
    def __init__(self, target):
        self.target = target
        self.started = time.monotonic()
        self.stats = {}
        self.corpus = (0, "0b")
        self.corpus_bytes = 0
        self.last_new = None
        # Tracked apart from `last_new` because libFuzzer fires NEW on a new
        # *feature*, and a feature is an edge or a new hit count on one it
        # already had. A run can add an input a second for minutes while the
        # edge count does not move — which is a corpus growing sideways, not a
        # fuzzer still finding its way into code. The edge clock is the one that
        # says a target is spent.
        self.last_edge = None
        self.best_cov = 0
        self.finds = []
        # The most recent line that was not a stats line, shown until the first
        # one arrives. Everything before fuzzing starts — cargo relinking the
        # target, libFuzzer counting the corpus — reaches this program and
        # nothing else, and dropping it silently leaves a blank terminal for as
        # long as the build takes. A blank terminal is indistinguishable from a
        # hung one, which is the one thing this must never look like.
        self.waiting_on = "starting"

    def take(self, line):
        """Reads one stats line, and says whether it was one."""
        stripped = line.strip()
        if stripped:
            self.waiting_on = stripped[:100]

        matched = False
        for name, pattern in FIELDS.items():
            found = pattern.search(line)
            if not found:
                continue
            matched = True
            if name == "corp":
                self.corpus_bytes = int(found.group(2)) * SCALE[found.group(3)]
                self.corpus = (
                    int(found.group(1)),
                    f"{found.group(2)} {found.group(3)}iB" if found.group(3) else f"{found.group(2)} B",
                )
            else:
                self.stats[name] = int(found.group(1))

        if not matched:
            return False

        covered = self.stats.get("cov", 0)
        if covered > self.best_cov:
            self.best_cov = covered
            self.last_edge = time.monotonic()

        event = EVENT.match(line)
        if event and event.group(1) == "NEW":
            self.last_new = time.monotonic()
            self.finds.append((self.age(), covered, self.corpus[0]))
            self.finds = self.finds[-5:]
        return True

    def age(self):
        return time.monotonic() - self.started

    def snapshot(self, state):
        """The screen's numbers as a dictionary, for `--json`.

        Both clocks are given as seconds of silence rather than as timestamps,
        because a reader wants the age and would otherwise have to reconstruct it
        from a clock that is not the one this ran on. `written_at` is wall time,
        which is what tells a collector the run behind this file has stopped.
        """

        def silence(when):
            return None if when is None else round(time.monotonic() - when, 1)

        return {
            "target": self.target,
            "state": state,
            "written_at": round(time.time(), 1),
            "uptime_s": round(self.age(), 1),
            "execs": self.stats.get("execs", 0),
            "exec_s": self.stats.get("exec_s", 0),
            "cov": self.stats.get("cov", 0),
            "ft": self.stats.get("ft", 0),
            "corpus_files": self.corpus[0],
            "corpus_bytes": self.corpus_bytes,
            "rss_mb": self.stats.get("rss", 0),
            "since_new_edge_s": silence(self.last_edge),
            "since_new_input_s": silence(self.last_new),
            "waiting_on": self.waiting_on,
        }

    def draw(self):
        def since(when):
            return "never" if when is None else f"{elapsed(time.monotonic() - when)} ago"

        # Nothing has been measured yet, so there is nothing to lay out. What
        # there is instead is whatever the toolchain last said, which is the
        # answer to "is this doing anything".
        if not self.stats:
            sys.stdout.write(
                CLEAR
                + f"\n  {BOLD}{self.target}{OFF}{DIM}   starting, {elapsed(self.age())} in{OFF}\n"
                + f"\n  {self.waiting_on}\n"
                + f"\n  {DIM}a rebuild lands here first, and takes minutes on a cold "
                f"target{OFF}\n"
            )
            sys.stdout.flush()
            return
        rows = [
            "",
            f"  {BOLD}{self.target}{OFF}{DIM}   running {elapsed(self.age())}{OFF}",
            "",
            f"  coverage   {thousands(self.stats.get('cov', 0)):>12} edges   "
            f"{thousands(self.stats.get('ft', 0)):>10} features",
            f"  corpus     {thousands(self.corpus[0]):>12} inputs  {self.corpus[1]:>16}",
            f"  speed      {thousands(self.stats.get('exec_s', 0)):>12} exec/s  "
            f"{thousands(self.stats.get('execs', 0)):>10} total",
            f"  memory     {thousands(self.stats.get('rss', 0)):>12} MiB",
            "",
            f"  {DIM}last input {since(self.last_new):>12}   the corpus grew{OFF}",
            f"  {BOLD}new edges  {since(self.last_edge):>12}{OFF}{DIM}   nothing here for a long "
            f"while means this target is spent{OFF}",
        ]

        if self.finds:
            rows += ["", f"  {DIM}recent finds{OFF}"]
            for at, cov, corp in self.finds:
                rows.append(f"    {DIM}{elapsed(at):>8}   cov {thousands(cov)}   corp {corp}{OFF}")

        rows.append("")
        sys.stdout.write(CLEAR + "\n".join(rows) + "\n")
        sys.stdout.flush()


def parse(argv):
    """`watch.py <target> [--json <path>]`, in either order."""
    rest = list(argv)
    path = None
    if "--json" in rest:
        at = rest.index("--json")
        if at + 1 >= len(rest):
            sys.stderr.write("watch.py: --json wants a path\n")
            raise SystemExit(2)
        path = rest[at + 1]
        del rest[at : at + 2]
    return (rest[0] if rest else "fuzzing"), path


def write_json(path, payload):
    """Rewritten whole, through a rename, so a reader never sees half a file."""
    if path is None:
        return
    tmp = f"{path}.{os.getpid()}"
    try:
        with open(tmp, "w") as handle:
            # A trailing newline so `cat *.json` over several of these is
            # readable a line at a time.
            handle.write(json.dumps(payload) + "\n")
        os.replace(tmp, path)
    except OSError:
        # A collector that has gone away is not a reason to stop fuzzing.
        try:
            os.unlink(tmp)
        except OSError:
            pass


def main():
    target, json_path = parse(sys.argv[1:])
    screen = Screen(target)
    # Escape codes belong to a terminal. Anywhere else the same stream is
    # being collected, and a repainting screen in a log is noise nobody can
    # read.
    live = sys.stdout.isatty()
    drawn = 0.0
    written = 0.0

    write_json(json_path, screen.snapshot("starting"))

    for line in sys.stdin:
        # Anything that smells like a crash ends the rendering for good: from
        # here on the raw stream is what the reader needs.
        if TROUBLE.search(line):
            crashed = screen.snapshot("crashed")
            crashed["trouble"] = line.strip()[:200]
            write_json(json_path, crashed)
            if live:
                sys.stdout.write(CLEAR)
            sys.stdout.write(line)
            sys.stdout.writelines(sys.stdin)
            sys.stdout.flush()
            return 1

        if not screen.take(line) and screen.stats:
            continue

        # Redrawn at most a few times a second. libFuzzer emits thousands of
        # lines a minute and a screen that repainted on each of them would cost
        # more than the fuzzing.
        now = time.monotonic()
        if live and now - drawn > 0.25:
            drawn = now
            screen.draw()
        # Slower than the screen. A reader polling every few seconds gains
        # nothing from a file rewritten four times a second.
        if now - written > 2.0:
            written = now
            write_json(json_path, screen.snapshot("fuzzing" if screen.stats else "starting"))

    if live:
        screen.draw()
    write_json(json_path, screen.snapshot("stopped"))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (KeyboardInterrupt, BrokenPipeError):
        sys.exit(130)
