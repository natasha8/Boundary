from argparse import ArgumentParser
from collections.abc import Sequence


def build_parser() -> ArgumentParser:
    return ArgumentParser(
        prog="boundary",
        description="Evidence-driven Web and API security scanner.",
    )


def main(argv: Sequence[str] | None = None) -> None:
    parser = build_parser()
    parser.parse_args(argv)
    parser.print_help()
