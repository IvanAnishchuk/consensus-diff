"""Scripted wire-protocol backend for harness tests. Not a consensus client.

Usage: python fake_backend.py <fork> <preset>
FAKE_MODE env var picks the behavior:
  ok            -> answer 'pass\\tok\\t<line-count>' to every request
  reject        -> answer 'fail\\treject\\tnope'
  noise-then-ok -> two banner lines first, then behave like ok
  die           -> exit after reading one request (before answering)
  die-once      -> if FAKE_DIE_ONCE_FLAG path absent: create it and exit 1;
                   if path exists: answer like ok (simulates a one-shot crash)
  garbage       -> emit a non-protocol line as the only answer, then behave like ok
  hang          -> read a request and sleep forever
  badargv       -> exit 2 immediately (unsupported fork/preset simulation)
"""

import os
import sys
import time


def main() -> None:
    mode = os.environ.get("FAKE_MODE", "ok")
    if mode == "badargv":
        sys.exit(2)
    if mode == "noise-then-ok":
        print("fake backend booting...")
        print("build ok")
        sys.stdout.flush()
    n = 0
    for _line in sys.stdin:
        n += 1
        if mode == "die":
            sys.exit(1)
        if mode == "die-once":
            flag_path = os.environ.get("FAKE_DIE_ONCE_FLAG", "")
            if not os.path.exists(flag_path):
                open(flag_path, "w").close()
                sys.exit(1)
        if mode == "hang":
            time.sleep(3600)
        if mode == "garbage" and n == 1:
            print("not a protocol line")
            sys.stdout.flush()
            continue
        if mode == "reject":
            print("fail\treject\tnope")
        else:
            print(f"pass\tok\t{n}")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
