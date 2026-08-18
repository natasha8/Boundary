import asyncio
from argparse import ArgumentParser, Namespace
from collections.abc import Sequence

from boundary.discovery import DiscoveryLimits
from boundary.resolver import SystemAddressResolver
from boundary.scan import ScanConfig, run_passive_scan
from boundary.scope import AddressPolicy, parse_target_url
from boundary.transport import RequestLimits


def build_parser() -> ArgumentParser:
    parser = ArgumentParser(
        prog="boundary",
        description="Evidence-driven Web and API security scanner.",
    )
    subparsers = parser.add_subparsers(dest="command", required=False)
    scan_parser = subparsers.add_parser("scan")
    scan_parser.add_argument("target")
    scan_parser.add_argument("--allow-origin", action="append", required=True)
    scan_parser.add_argument(
        "--address-policy",
        choices=[policy.value for policy in AddressPolicy],
        required=True,
    )
    scan_parser.add_argument("--max-pages", type=int, required=True)
    scan_parser.add_argument("--max-depth", type=int, required=True)
    scan_parser.add_argument("--max-redirects", type=int, required=True)
    scan_parser.add_argument("--max-body-bytes", type=int, required=True)
    scan_parser.add_argument("--connect-timeout", type=float)
    scan_parser.add_argument("--read-timeout", type=float)
    scan_parser.add_argument("--write-timeout", type=float)
    scan_parser.add_argument("--pool-timeout", type=float)
    return parser


def _run_scan(args: Namespace) -> None:
    target = parse_target_url(args.target)
    allowed_origins = tuple(parse_target_url(raw).origin for raw in args.allow_origin)
    discovery_limits = DiscoveryLimits(
        max_pages=args.max_pages,
        max_depth=args.max_depth,
    )
    request_limits = RequestLimits(
        max_body_bytes=args.max_body_bytes,
        connect_timeout=args.connect_timeout,
        read_timeout=args.read_timeout,
        write_timeout=args.write_timeout,
        pool_timeout=args.pool_timeout,
    )
    config = ScanConfig(
        target=target,
        allowed_origins=allowed_origins,
        policy=AddressPolicy(args.address_policy),
        resolver=SystemAddressResolver(),
        request_limits=request_limits,
        max_redirects=args.max_redirects,
        discovery_limits=discovery_limits,
    )
    result = asyncio.run(run_passive_scan(config))
    print(f"{len(result.findings)} findings")


def main(argv: Sequence[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "scan":
        _run_scan(args)
        return
    parser.print_help()
