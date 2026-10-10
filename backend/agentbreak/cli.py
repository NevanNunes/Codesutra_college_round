"""Reserved regression CLI entry point, owned by session A."""

import sys


def main() -> int:
    print(
        "AgentBreak regression CLI is not implemented in this scaffold.",
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
