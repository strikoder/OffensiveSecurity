#!/usr/bin/env python3
# /// script
# dependencies = ["requests", "PyPDF2", "python-docx", "rich"]
# ///

"""
bulk_fetch_downloader.py - Bulk URL fetcher and keyword scanner.

Iterates over date ranges, numeric ranges, or wordlists to download
and scan files. Supports .pdf, .txt, .doc, .docx with keyword scanning
and metadata extraction. Files are saved to ./downloads/ by default.

Install deps (first time only):
    uv add --script bulk_fetch_downloader.py requests PyPDF2 python-docx rich

Examples:
    # HTB Intelligence - known URL: http://intelligence.htb/documents/2020-12-15-upload.pdf
    uv run bulk_fetch_downloader.py --url "http://intelligence.htb/documents/%s-upload.pdf" --ext .pdf --mode date --start 2020-01-01 --end 2020-12-31

    # Numeric range
    uv run bulk_fetch_downloader.py --url "http://target.htb/files/%s.docx" --ext .docx --mode numeric --start 1 --end 500

    # Wordlist
    uv run bulk_fetch_downloader.py --url "http://target.htb/uploads/%s.txt" --ext .txt --mode wordlist --wordlist hashes.txt

    # Custom keywords + parallel workers
    uv run bulk_fetch_downloader.py --url "http://target.htb/docs/%s.pdf" --ext .pdf --mode numeric --start 1 --end 1000 --keywords admin,secret,token,api_key --workers 10

Supported extensions:
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
from pathlib import Path
from typing import Callable, Generator

import requests
from rich.console import Console
from rich.progress import BarColumn, MofNCompleteColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn, TimeRemainingColumn
from rich.table import Table
from rich import print as rprint

console = Console()

DEFAULT_KEYWORDS = "user,password,pass,username,account,login,service,ssh,old,svc,api,key,script,hash"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="bulk_fetch_downloader.py",
        description="Bulk URL fetcher and keyword scanner for date/numeric/wordlist patterns.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    parser.add_argument("--url", required=True, metavar="PATTERN",
        help="URL pattern with %%s as placeholder. e.g. 'http://target.htb/docs/%%s-upload.pdf'")
    parser.add_argument("--ext", required=True, metavar="EXT",
        help="File extension. e.g. .pdf .txt .docx .doc")
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

    args = parser.parse_args()

    if args.mode in ("date", "numeric") and not (args.start and args.end):
        parser.error(f"--mode {args.mode} requires both --start and --end")
    if args.mode == "wordlist" and not args.wordlist:
        parser.error("--mode wordlist requires --wordlist FILE")

    if not args.ext.startswith("."):
        args.ext = "." + args.ext
    args.ext = args.ext.lower()

    args.keywords = [k.strip().lower() for k in args.keywords.split(",") if k.strip()]

    return args


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


def md5(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


def download_and_scan(url, ext, filename, keywords, timeout, delay) -> dict:
    result: dict = {"url": url, "status": None, "md5": None, "metadata": {}, "matches": [], "error": None}
    try:
        resp = requests.get(url, timeout=timeout)
        result["status"] = resp.status_code

        if resp.status_code == 200:
            result["md5"] = md5(resp.content)
            Path(filename).write_bytes(resp.content)

            handler = HANDLERS.get(ext)
            if handler:
                parsed = handler(resp.content, keywords)
                result["metadata"] = parsed["metadata"]
                result["matches"]  = parsed["matches"]
                if parsed["error"]:
                    result["error"] = parsed["error"]

    except requests.RequestException as exc:
        result["error"] = str(exc)

    if delay > 0:
        time.sleep(delay)

    return result


def save_metadata(results: list[dict]) -> None:
    all_meta: dict[str, set] = {}
    for r in results:
        for k, v in r.get("metadata", {}).items():
            all_meta.setdefault(k, set()).add(v)
    for field, values in all_meta.items():
        out = Path(f"{field.lower()}s.txt")
        out.write_text("\n".join(sorted(values)))
        console.print(f"[dim]  -> {out}[/]")


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
                rprint(f"  [dim]{m['snippet'][:200]!r}[/]")

    for field, values in all_meta.items():
        console.rule(f"[bold green]{field}s")
        for v in sorted(values):
            rprint(f"  {v}")


def main() -> None:
    if len(sys.argv) == 1:
        console.print("""
no arguments given. example:

    uv run bulk_fetch_downloader.py --url "http://intelligence.htb/documents/%s-upload.pdf" --ext .pdf --mode date --start 2020-01-01 --end 2020-12-31

run with --help for full usage.
""")
        sys.exit(0)

    args = parse_args()

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

    console.print(f"[bold]starting:[/] {total} URLs, ext={args.ext}, mode={args.mode}, workers={args.workers}")

    all_results: list[dict] = []

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
            args.timeout, 0.0 if args.workers > 1 else args.delay,
        )

    with progress:
        task_id = progress.add_task("fetching...", total=len(tasks))

        if args.workers > 1:
            with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
                futures = {pool.submit(run_one, t): t for t in tasks}
                for future in concurrent.futures.as_completed(futures):
                    r = future.result()
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
