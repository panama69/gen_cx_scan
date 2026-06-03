#!/usr/bin/env python3
import argparse
import json
import os
import re
import shlex
import subprocess
import sys
from datetime import datetime
from time import perf_counter


def timestamp_str():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def timestamp_print(message="", file=sys.stderr):
    print(f"[{timestamp_str()}] {message}", file=file)


def verbose_print(message, verbose, file=sys.stderr):
    if verbose:
        timestamp_print(message, file=file)


def format_duration(seconds):
    return f"{seconds:.3f}s"


def run_syft_scan(image_name, verbose=False):
    """Runs syft scan on the image and returns the parsed JSON output."""
    timestamp_print(f"[*] Running Syft scan on image: {image_name}...", file=sys.stderr)
    if verbose:
        timestamp_print(f"    command: syft scan {image_name} -o json", file=sys.stderr)
    try:
        result = subprocess.run(
            ["syft", "scan", image_name, "-o", "json"],
            capture_output=True,
            text=True,
            check=True,
        )
        if verbose:
            timestamp_print("[+] Syft scan completed successfully.", file=sys.stderr)
            timestamp_print("[+] Syft raw output:", file=sys.stderr)
            for raw_line in result.stdout.splitlines():
                timestamp_print(raw_line, file=sys.stderr)
        return json.loads(result.stdout)
    except subprocess.CalledProcessError as e:
        timestamp_print(f"[-] Error executing Syft: {e.stderr}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError:
        timestamp_print(
            "[-] Error: Failed to parse Syft output as JSON.", file=sys.stderr
        )
        sys.exit(1)


def resolve_cx_path(cx_path, verbose=False):
    """Resolve cx-path to an executable, supporting directory paths."""
    cx_path = os.path.expanduser(cx_path)
    if os.path.isdir(cx_path):
        verbose_print(
            f"[>] cx-path is a directory; searching for executable inside: {cx_path}",
            verbose,
        )
        candidates = ["cx", "cx.sh", "ast-cli_2.3.51_darwin_x64"]
        for candidate in candidates:
            candidate_path = os.path.join(cx_path, candidate)
            if os.path.isfile(candidate_path) and os.access(candidate_path, os.X_OK):
                verbose_print(f"[+] Found executable: {candidate_path}", verbose)
                return candidate_path
        timestamp_print(
            "[-] Error: cx-path is a directory but no executable was found inside.",
            file=sys.stderr,
        )
        sys.exit(1)

    if os.path.isfile(cx_path):
        if os.access(cx_path, os.X_OK):
            return cx_path
        timestamp_print(
            f"[-] Error: cx-path exists but is not executable: {cx_path}",
            file=sys.stderr,
        )
        sys.exit(1)

    timestamp_print(f"[-] Error: cx-path does not exist: {cx_path}", file=sys.stderr)
    sys.exit(1)


def extract_group_ids(syft_data, target_folders):
    """Parses Syft JSON data and extracts unique Maven Group IDs found in target folders.

    Uses a fallback chain matching the provided jq criteria:
    - prefer metadata.pomProperties.groupId
    - fallback to the PURL namespace if groupId is missing
    - only include artifacts whose locations start with a target folder
    """
    group_ids = set()

    # Ensure paths end with a slash for clean matching
    normalized_folders = [
        f if f.endswith("/") else f + "/" for f in target_folders
    ]

    artifacts = syft_data.get("artifacts", [])
    for artifact in artifacts:
        metadata = artifact.get("metadata") or {}
        pom_properties = metadata.get("pomProperties") or {}
        group_id = pom_properties.get("groupId")

        if not group_id:
            purl = artifact.get("purl")
            if isinstance(purl, str) and purl:
                purl_base = purl.split("?", 1)[0]
                purl_parts = purl_base.split("/")
                if len(purl_parts) > 1 and purl_parts[1]:
                    group_id = purl_parts[1]

        if not group_id:
            continue

        locations = artifact.get("locations", [])
        for loc in locations:
            path = loc.get("path", "")
            if any(path.startswith(folder) for folder in normalized_folders):
                group_ids.add(group_id)
                break

    return sorted(list(group_ids))


def main():
    parser = argparse.ArgumentParser(
        description="Extract Maven Group IDs via Syft to dynamically build a Checkmarx One Container Scan command."
    )

    # Required Arguments
    parser.add_argument(
        "--image", required=True, help="The Docker image to scan (e.g., apache/kafka:latest)"
    )
    parser.add_argument(
        "--project", required=True, help="The Checkmarx One project name"
    )
    parser.add_argument(
        "--folders",
        required=True,
        nargs="+",
        help="One or more target folders inside the container to inspect (e.g., /opt/kafka/libs/)",
    )

    # Optional Arguments
    parser.add_argument(
        "--branch",
        default="main",
        help="The branch name for Checkmarx One (default: main)",
    )
    parser.add_argument(
        "--cx-path",
        default="./cx",
        help="Path to the Checkmarx One executable (default: ./cx)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show the generated cx command without executing it.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Show detailed step-by-step execution and debug output.",
    )

    args = parser.parse_args()
    cx_path = resolve_cx_path(args.cx_path, args.verbose)

    total_start = perf_counter()
    syft_start = perf_counter()

    # 1. Run Syft
    verbose_print("[>] Step 1: Run Syft scan and parse JSON output.", args.verbose)
    syft_output = run_syft_scan(args.image, args.verbose)
    syft_elapsed = perf_counter() - syft_start

    # 2. Process and Filter Group IDs
    verbose_print(
        f"[>] Step 2: Extract Maven Group IDs from folders {args.folders}.",
        args.verbose,
    )
    group_ids = extract_group_ids(syft_output, args.folders)

    if not group_ids:
        timestamp_print(
            f"[-] No Maven Group IDs found in folders: {args.folders}. Generating fallback command without filter.",
            file=sys.stderr,
        )
        filter_str = ""
    else:
        # 3. Turn the Group IDs into Checkmarx regex strings (e.g., ^org\.apache.*)
        cx_filters = [f"^{re.escape(gid)}.*" for gid in group_ids]
        filter_str = ",".join(cx_filters)
        timestamp_print(
            f"[+] Found {len(group_ids)} unique Maven Group IDs.",
            file=sys.stderr,
        )
        verbose_print(f"    group IDs: {group_ids}", args.verbose)
        verbose_print(f"    package filter: {filter_str}", args.verbose)

    # 4. Construct Checkmarx One Command
    verbose_print("[>] Step 3: Build the Checkmarx One scan command.", args.verbose)
    cx_cmd = [
        cx_path,
        "scan",
        "create",
        "--project-name",
        args.project,
        "-s",
        ".",
        "--scan-types",
        "container-security",
        "--container-images",
        args.image,
        "--branch",
        args.branch,
    ]

    if filter_str:
        cx_cmd.extend(["--containers-package-filter", filter_str])

    # Output the generated command line string
    command_text = shlex.join(cx_cmd)
    print()
    timestamp_print("" + "=" * 40 + " GENERATED CHECKMARX COMMAND " + "=" * 40, file=sys.stdout)
    timestamp_print(command_text, file=sys.stdout)
    timestamp_print("=" * 109, file=sys.stdout)

    cx_elapsed = 0.0
    if args.dry_run:
        timestamp_print("[i] Dry run enabled; not executing the cx command.", file=sys.stderr)
        total_elapsed = perf_counter() - total_start
        timestamp_print(
            "[+] Timing summary: Syft scan took %s, cx execution skipped, total elapsed %s." % (
                format_duration(syft_elapsed), format_duration(total_elapsed)
            ),
            file=sys.stderr,
        )
        return

    try:
        verbose_print("[>] Step 4: Execute the generated Checkmarx command.", args.verbose)
        timestamp_print("[*] Executing Checkmarx command...", file=sys.stderr)
        cx_start = perf_counter()
        subprocess.run(cx_cmd, check=True)
        cx_elapsed = perf_counter() - cx_start
    except subprocess.CalledProcessError as e:
        cx_elapsed = perf_counter() - cx_start if "cx_start" in locals() else 0.0
        timestamp_print(f"[-] Error executing cx: {e}", file=sys.stderr)
        total_elapsed = perf_counter() - total_start
        timestamp_print(
            "[+] Timing summary: Syft %s, cx %s, total %s." % (
                format_duration(syft_elapsed), format_duration(cx_elapsed), format_duration(total_elapsed)
            ),
            file=sys.stderr,
        )
        sys.exit(e.returncode)

    total_elapsed = perf_counter() - total_start
    timestamp_print(
        "[+] Timing summary: Syft %s, cx %s, other overhead %s, total %s." % (
            format_duration(syft_elapsed),
            format_duration(cx_elapsed),
            format_duration(total_elapsed - syft_elapsed - cx_elapsed),
            format_duration(total_elapsed),
        ),
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
