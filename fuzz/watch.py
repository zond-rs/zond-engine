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
"""

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
# **Anchored, and case-sensitive.** The loose version of this matched `ERROR`
# anywhere in a line, which is a word that turns up in ordinary output: libFuzzer
# prints `NEW_FUNC[1/1]: 0x... in <mangled symbol>` whenever it reaches a new
# function, and a Rust symbol for anything touching `serde_json::error::Error`
# carries it. Every import target hit one within seconds of starting and the
# screen was never drawn again.
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

    def take(self, line):
        """Reads one stats line, and says whether it was one."""
        matched = False
        for name, pattern in FIELDS.items():
            found = pattern.search(line)
            if not found:
                continue
            matched = True
            if name == "corp":
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

    def draw(self):
        def since(when):
            return "never" if when is None else f"{elapsed(time.monotonic() - when)} ago"
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


def main():
    target = sys.argv[1] if len(sys.argv) > 1 else "fuzzing"
    screen = Screen(target)
    drawn = 0.0

    for line in sys.stdin:
        # Anything that smells like a crash ends the rendering for good: from
        # here on the raw stream is what the reader needs.
        if TROUBLE.search(line):
            sys.stdout.write(CLEAR)
            sys.stdout.write(line)
            sys.stdout.writelines(sys.stdin)
            sys.stdout.flush()
            return 1

        if not screen.take(line):
            continue

        # Redrawn at most a few times a second. libFuzzer emits thousands of
        # lines a minute and a screen that repainted on each of them would cost
        # more than the fuzzing.
        now = time.monotonic()
        if now - drawn > 0.25:
            drawn = now
            screen.draw()

    screen.draw()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (KeyboardInterrupt, BrokenPipeError):
        sys.exit(130)
