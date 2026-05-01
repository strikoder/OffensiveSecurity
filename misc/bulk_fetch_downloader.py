#!/usr/bin/env python3
# /// script
# dependencies = ["requests", "PyPDF2", "python-docx", "rich"]
# ///

"""
bulk_fetch_downloader.py - Bulk URL fetcher and keyword scanner.

Iterates over date ranges, numeric ranges, or wordlists to download
and scan files. Supports .pdf, .txt, .doc, .docx with keyword scanning
and metadata extraction. Files are saved to ./downloads/ by default.

The --ext flag is optional: it is auto-detected from the URL pattern.
Supply it explicitly only if the URL has no recognisable extension.

Install deps (first time only):
    uv add --script bulk_fetch_downloader.py requests PyPDF2 python-docx rich

Examples:
    # HTB Intelligence - known URL: http://intelligence.htb/documents/2020-12-15-upload.pdf
    uv run bulk_fetch_downloader.py --url "http://intelligence.htb/documents/%s-upload.pdf" --mode date --start 2020-01-01 --end 2020-12-31

    # Numeric range
    uv run bulk_fetch_downloader.py --url "http://target.htb/files/%s.docx" --mode numeric --start 1 --end 500

    # Wordlist
    uv run bulk_fetch_downloader.py --url "http://target.htb/uploads/%s.txt" --mode wordlist --wordlist hashes.txt

    # Self-signed / HTB HTTPS box
    uv run bulk_fetch_downloader.py --url "https://target.htb/docs/%s.pdf" --mode numeric --start 1 --end 100 --no-verify

    # Custom keywords + parallel workers
    uv run bulk_fetch_downloader.py --url "http://target.htb/docs/%s.pdf" --mode numeric --start 1 --end 1000 --keywords admin,secret,token,api_key --workers 10

Supported extensions (auto-detected from URL):
    .pdf   - text + metadata (/Creator, /Author, /Title, /Producer)
    .txt   - raw UTF-8 text
    .docx  - paragraphs + core properties (author, title, subject)
    .doc   - best-effort binary text scrape
    other  - downloaded and saved, no scanning

Output:
    downloads/    all downloaded files
    creators.txt, authors.txt, titles.txt, etc. (one per metadata field found)
"""

import argparse
import concurrent.futures
import datetime
import hashlib
import io
import re
import sys
import time
import urllib3
from pathlib import Path
from typing import Callable, Generator

import requests
from rich.console import Console
from rich.progress import BarColumn, MofNCompleteColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn, TimeRemainingColumn
from rich.table import Table
from rich import print as rprint

console = Console()

DEFAULT_KEYWORDS = "user,password,pass,username,account,login,service,ssh,old,svc,api,key,script,hash"

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)

DEFAULT_HEADERS = {
    "User-Agent": USER_AGENT,
    "Accept": "*/*",
}


# ---------------------------------------------------------------------------
# Extension helpers
# ---------------------------------------------------------------------------

def detect_ext(url_pattern: str) -> str | None:
    """
    Try to pull a file extension from the URL pattern, ignoring the %s
    placeholder.  Returns e.g. '.pdf', or None if nothing recognisable is found.
    """
    # Strip the placeholder so it doesn't confuse the path parser
    clean = url_pattern.replace("%s", "PLACEHOLDER")
    # Grab everything after the last '/' and before any '?'
    filename_part = clean.split("/")[-1].split("?")[0]
    match = re.search(r"(\.[a-zA-Z0-9]+)$", filename_part)
    if match:
        return match.group(1).lower()
    return None


def resolve_ext(args_ext: str | None, url_pattern: str) -> str:
    """
    Return the extension to use, auto-detecting from the URL when --ext is
    not supplied.  Exits with a helpful message if neither works.
    """
    if args_ext:
        ext = args_ext if args_ext.startswith(".") else "." + args_ext
        return ext.lower()

    detected = detect_ext(url_pattern)
    if detected:
        console.print(f"[dim]auto-detected extension:[/] [bold]{detected}[/]")
        return detected

    console.print(
        "[red]could not auto-detect extension from URL.[/] "
        "Please supply [bold]--ext[/] explicitly (e.g. --ext .pdf)"
    )
    sys.exit(1)


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="bulk_fetch_downloader.py",
        description="Bulk URL fetcher and keyword scanner for date/numeric/wordlist patterns.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    parser.add_argument("--url", required=True, metavar="PATTERN",
        help="URL pattern with %%s as placeholder. e.g. 'http://target.htb/docs/%%s-upload.pdf'")
    parser.add_argument("--ext", default=None, metavar="EXT",
        help="File extension override (e.g. .pdf). Auto-detected from --url when omitted.")
    parser.add_argument("--mode", required=True, choices=["date", "numeric", "wordlist"],
        help="Iteration mode: date | numeric | wordlist")
    parser.add_argument("--start", metavar="VAL",
        help="date: YYYY-MM-DD  |  numeric: integer")
    parser.add_argument("--end", metavar="VAL",
        help="date: YYYY-MM-DD  |  numeric: integer")
    parser.add_argument("--wordlist", metavar="FILE",
        help="Path to wordlist file, one value per line (wordlist mode only)")
    parser.add_argument("--keywords", metavar="LIST", default=DEFAULT_KEYWORDS,
        help=f"Comma-separated keywords to scan for (default: {DEFAULT_KEYWORDS})")
    parser.add_argument("--workers", type=int, default=1, metavar="N",
        help="Parallel download workers (default: 1)")
    parser.add_argument("--delay", type=float, default=0.0, metavar="SEC",
        help="Delay between requests in seconds (default: 0.0, ignored when --workers > 1)")
    parser.add_argument("--timeout", type=int, default=10, metavar="SEC",
        help="HTTP request timeout in seconds (default: 10)")
    parser.add_argument("--out-dir", default="downloads", metavar="DIR",
        help="Directory to save downloaded files (default: ./downloads)")
    parser.add_argument("--no-verify", action="store_true",
        help="Disable TLS certificate verification (useful for self-signed certs on HTB/CTF boxes)")

    args = parser.parse_args()

    if args.mode in ("date", "numeric") and not (args.start and args.end):
        parser.error(f"--mode {args.mode} requires both --start and --end")
    if args.mode == "wordlist" and not args.wordlist:
        parser.error("--mode wordlist requires --wordlist FILE")

    if args.workers > 1 and args.delay > 0:
        console.print("[yellow]warning: --delay is ignored when --workers > 1[/]")

    args.keywords = [k.strip().lower() for k in args.keywords.split(",") if k.strip()]
    args.ext = resolve_ext(args.ext, args.url)

    return args


# ---------------------------------------------------------------------------
# File handlers
# ---------------------------------------------------------------------------

def handle_pdf(content: bytes, keywords: list[str]) -> dict:
    from PyPDF2 import PdfReader
    result: dict = {"metadata": {}, "matches": [], "error": None}
    try:
        reader = PdfReader(io.BytesIO(content))
        if reader.metadata:
            for field in ("/Creator", "/Author", "/Title", "/Producer"):
                val = reader.metadata.get(field)
                if val:
                    result["metadata"][field.lstrip("/")] = val
        for page_num, page in enumerate(reader.pages, 1):
            text = page.extract_text() or ""
            hits = [k for k in keywords if k in text.lower()]
            if hits:
                result["matches"].append({"page": page_num, "keywords": hits, "snippet": text[:300].strip()})
    except Exception as exc:
        result["error"] = str(exc)
    return result


def handle_txt(content: bytes, keywords: list[str]) -> dict:
    result: dict = {"metadata": {}, "matches": [], "error": None}
    try:
        text = content.decode("utf-8", errors="replace")
        hits = [k for k in keywords if k in text.lower()]
        if hits:
            result["matches"].append({"page": 1, "keywords": hits, "snippet": text[:300].strip()})
    except Exception as exc:
        result["error"] = str(exc)
    return result


def handle_docx(content: bytes, keywords: list[str]) -> dict:
    import docx
    result: dict = {"metadata": {}, "matches": [], "error": None}
    try:
        doc = docx.Document(io.BytesIO(content))
        cp = doc.core_properties
        for attr in ("author", "title", "subject", "creator"):
            val = getattr(cp, attr, None)
            if val:
                result["metadata"][attr] = val
        full_text = "\n".join(p.text for p in doc.paragraphs)
        hits = [k for k in keywords if k in full_text.lower()]
        if hits:
            result["matches"].append({"page": 1, "keywords": hits, "snippet": full_text[:300].strip()})
    except Exception as exc:
        result["error"] = str(exc)
    return result


def handle_doc(content: bytes, keywords: list[str]) -> dict:
    result: dict = {"metadata": {}, "matches": [], "error": None}
    try:
        text = content.decode("latin-1", errors="replace")
        text = re.sub(r"[^\x20-\x7E\n\t]", " ", text)
        text = re.sub(r" {4,}", " ", text).strip()
        hits = [k for k in keywords if k in text.lower()]
        if hits:
            result["matches"].append({"page": 1, "keywords": hits, "snippet": text[:300].strip()})
    except Exception as exc:
        result["error"] = str(exc)
    return result


HANDLERS: dict[str, Callable[[bytes, list[str]], dict]] = {
    ".pdf":  handle_pdf,
    ".txt":  handle_txt,
    ".docx": handle_docx,
    ".doc":  handle_doc,
}


# ---------------------------------------------------------------------------
# Range generators
# ---------------------------------------------------------------------------

def date_range(start: str, end: str) -> Generator[str, None, None]:
    cur   = datetime.datetime.strptime(start, "%Y-%m-%d").date()
    end_d = datetime.datetime.strptime(end, "%Y-%m-%d").date()
    while cur <= end_d:
        yield cur.strftime("%Y-%m-%d")
        cur += datetime.timedelta(days=1)


def numeric_range(start: int, end: int) -> Generator[str, None, None]:
    for i in range(start, end + 1):
        yield str(i)


def wordlist_range(path: str) -> Generator[str, None, None]:
    with open(path) as fh:
        for line in fh:
            v = line.strip()
            if v:
                yield v


def total_count(args: argparse.Namespace) -> int:
    if args.mode == "date":
        s = datetime.datetime.strptime(args.start, "%Y-%m-%d").date()
        e = datetime.datetime.strptime(args.end, "%Y-%m-%d").date()
        return (e - s).days + 1
    if args.mode == "numeric":
        return int(args.end) - int(args.start) + 1
    return sum(1 for line in open(args.wordlist) if line.strip())


# ---------------------------------------------------------------------------
# Core download + scan
# ---------------------------------------------------------------------------

def md5(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


def download_and_scan(url, ext, filename, keywords, timeout, delay, verify) -> dict:
    result: dict = {"url": url, "status": None, "md5": None, "metadata": {}, "matches": [], "error": None}
    try:
        resp = requests.get(url, timeout=timeout, headers=DEFAULT_HEADERS, verify=verify)
        result["status"] = resp.status_code

        if resp.status_code == 200:
            result["md5"] = md5(resp.content)
            try:
                Path(filename).write_bytes(resp.content)
            except OSError as exc:
                result["error"] = f"save failed: {exc}"

            handler = HANDLERS.get(ext)
            if handler:
                parsed = handler(resp.content, keywords)
                result["metadata"] = parsed["metadata"]
                result["matches"]  = parsed["matches"]
                if parsed["error"]:
                    result["error"] = parsed["error"]

    except requests.exceptions.SSLError as exc:
        result["error"] = f"SSL error: {exc}"
        result["_hint"] = "ssl"
    except requests.exceptions.ConnectionError as exc:
        result["error"] = f"connection error: {exc}"
        result["_hint"] = "connection"
    except requests.exceptions.Timeout:
        result["error"] = "request timed out"
        result["_hint"] = "timeout"
    except requests.RequestException as exc:
        result["error"] = str(exc)

    if delay > 0:
        time.sleep(delay)

    return result


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

def save_metadata(results: list[dict]) -> None:
    all_meta: dict[str, set] = {}
    for r in results:
        for k, v in r.get("metadata", {}).items():
            all_meta.setdefault(k, set()).add(v)
    for field, values in all_meta.items():
        out = Path(f"{field.lower()}s.txt")
        try:
            out.write_text("\n".join(sorted(values)))
            console.print(f"[dim]  -> {out}[/]")
        except OSError as exc:
            console.print(f"[red]could not write {out}: {exc}[/]")


def print_hints(results: list[dict]) -> None:
    """Collect error hints and print actionable suggestions at the end."""
    hints: set[str] = set()
    error_count = sum(1 for r in results if r.get("error"))

    for r in results:
        h = r.get("_hint")
        if h:
            hints.add(h)

    if not error_count:
        return

    console.rule("[bold red]hints")
    console.print(f"[yellow]{error_count} request(s) encountered errors.[/]\n")

    if "ssl" in hints:
        console.print(
            "[bold]SSL / certificate errors detected.[/]\n"
            "  -> The target is using a self-signed or invalid certificate.\n"
            "  -> Re-run with [bold cyan]--no-verify[/] to skip TLS verification.\n"
            "  -> Example: add [bold cyan]--no-verify[/] to your command.\n"
        )
    if "connection" in hints:
        console.print(
            "[bold]Connection errors detected.[/]\n"
            "  -> Check that the host is reachable and the port is correct.\n"
            "  -> If targeting an HTB box, make sure your VPN is active.\n"
            "  -> Try [bold cyan]ping[/] or [bold cyan]curl[/] the URL manually to confirm.\n"
        )
    if "timeout" in hints:
        console.print(
            "[bold]Timeout errors detected.[/]\n"
            "  -> The server is slow or unreachable.\n"
            "  -> Try increasing [bold cyan]--timeout[/] (current default: 10s).\n"
            "  -> Reduce [bold cyan]--workers[/] if you are hammering the target.\n"
        )
    if not hints and error_count:
        # Generic fallback for errors without a specific hint
        sample_errors = list({r["error"] for r in results if r.get("error")})[:3]
        console.print("[bold]Other errors occurred:[/]")
        for e in sample_errors:
            console.print(f"  [dim]{e}[/]")
        console.print(
            "\n  -> Check [bold cyan]--url[/] pattern, [bold cyan]--ext[/], and network access.\n"
            "  -> If the server uses HTTPS with a bad cert, add [bold cyan]--no-verify[/].\n"
        )


def print_summary(results: list[dict]) -> None:
    found   = [r for r in results if r["status"] == 200]
    matches = [r for r in found if r["matches"]]

    all_meta: dict[str, set] = {}
    for r in found:
        for k, v in r.get("metadata", {}).items():
            all_meta.setdefault(k, set()).add(v)

    table = Table(title="Summary", header_style="bold cyan", show_lines=True)
    table.add_column("Metric", style="dim")
    table.add_column("Value", justify="right")
    table.add_row("Total tried",             str(len(results)))
    table.add_row("Downloaded (200)",         str(len(found)))
    table.add_row("Files with keyword hits",  str(len(matches)))
    for field, values in all_meta.items():
        table.add_row(f"Unique {field}s", str(len(values)))
    console.print(table)

    if matches:
        console.rule("[bold red]Keyword Matches")
        for r in matches:
            rprint(f"\n[bold yellow]{r['url']}[/]  [dim](md5: {r['md5']})[/]")
            for m in r["matches"]:
                rprint(f"  page {m['page']} - {', '.join(m['keywords'])}")
                rprint(f"  [dim]{m['snippet'][:300]!r}[/]")

    for field, values in all_meta.items():
        console.rule(f"[bold green]{field}s")
        for v in sorted(values):
            rprint(f"  {v}")

    print_hints(results)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    if len(sys.argv) == 1:
        console.print("""
no arguments given. example:

    uv run bulk_fetch_downloader.py --url "http://intelligence.htb/documents/%s-upload.pdf" --mode date --start 2020-01-01 --end 2020-12-31

run with --help for full usage.
""")
        sys.exit(0)

    args = parse_args()

    # Suppress urllib3 InsecureRequestWarning when --no-verify is set
    if args.no_verify:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        console.print("[yellow]warning: TLS certificate verification is disabled (--no-verify)[/]")

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    if args.ext not in HANDLERS:
        console.print(f"[yellow]no scanner for {args.ext}, will download only[/]")

    if args.mode == "date":
        gen = date_range(args.start, args.end)
    elif args.mode == "numeric":
        gen = numeric_range(int(args.start), int(args.end))
    else:
        gen = wordlist_range(args.wordlist)

    total = total_count(args)
    tasks = [(args.url % v, str(out_dir / f"{v}{args.ext}")) for v in gen]

    console.print(
        f"[bold]starting:[/] {total} URLs, ext={args.ext}, mode={args.mode}, "
        f"workers={args.workers}, verify={'yes' if not args.no_verify else '[red]no[/]'}"
    )

    all_results: list[dict] = []
    verify = not args.no_verify

    progress = Progress(
        SpinnerColumn(),
        TextColumn("{task.description}"),
        BarColumn(),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        TimeRemainingColumn(),
        console=console,
    )

    def run_one(task):
        url, fname = task
        return download_and_scan(
            url, args.ext, fname, args.keywords,
            args.timeout,
            0.0 if args.workers > 1 else args.delay,
            verify,
        )

    with progress:
        task_id = progress.add_task("fetching...", total=len(tasks))

        if args.workers > 1:
            with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
                futures = {pool.submit(run_one, t): t for t in tasks}
                for future in concurrent.futures.as_completed(futures):
                    try:
                        r = future.result()
                    except Exception as exc:
                        r = {"url": "unknown", "status": None, "md5": None,
                             "metadata": {}, "matches": [], "error": str(exc)}
                    all_results.append(r)
                    if r["status"] == 200:
                        progress.console.print(f"[green]+[/] {r['url']}  [dim]{r['md5']}[/]")
                    progress.advance(task_id)
        else:
            for t in tasks:
                r = run_one(t)
                all_results.append(r)
                if r["status"] == 200:
                    progress.console.print(f"[green]+[/] {r['url']}  [dim]{r['md5']}[/]")
                progress.advance(task_id)

    console.print()
    save_metadata(all_results)
    print_summary(all_results)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\ninterrupted")
        sys.exit(130)
    except ImportError as exc:
        console.print(f"missing dependency: {exc}")
        console.print("run: uv add --script bulk_fetch_downloader.py requests PyPDF2 python-docx rich")
        sys.exit(1)
