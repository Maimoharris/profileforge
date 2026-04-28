#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════╗
║           OSINT WORDLIST GENERATOR v1.0                  ║
║     For authorized penetration testing use only          ║
╚══════════════════════════════════════════════════════════╝

Generates targeted password wordlists from social engineering
/ OSINT data. Two modes:
  1. FILE MODE   — reads a structured .txt profile file
  2. INTERACTIVE — prompts for personal info step-by-step

Usage:
  python3 wordlist_gen.py -f profile.txt -o wordlist.txt
  python3 wordlist_gen.py -i -o wordlist.txt
  python3 wordlist_gen.py -i               (saves to <name>_wordlist.txt)
"""

import argparse
import itertools
import os
import re
import sys
import threading
import time
import queue
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime


# ─────────────────────────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────────────────────────

BANNER = r"""
  ___  ___ ___ _  _ _____   __  _____ ___ _  _
 / _ \/ __|_ _| \| |_   _| |\ \/ / __| __| \| |
| (_) \__ \| || .` | | |   | >  <| (_ | _|| .` |
 \___/|___/___|_|\_| |_|  |_/_/\_\___|___|_|\_|

         OSINT Wordlist Generator v1.0
    For authorized penetration testing only.
"""

SPECIAL_CHARS   = ["!", "@", "#", "$", "%", "&", "*", "?", ".", "_", "-"]
COMMON_SUFFIXES = [
    "", "1", "12", "123", "1234", "12345", "123456",
    "!", "!!", "!@#", "@", "#", "$", "2024", "2025",
    "0", "00", "007", "01", "69", "99",
]
COMMON_PREFIXES = ["", "the", "my", "i", "mr", "mrs", "ms", "dr"]

LEET_MAP = {
    "a": ["a", "@", "4"],
    "e": ["e", "3"],
    "i": ["i", "1", "!"],
    "o": ["o", "0"],
    "s": ["s", "$", "5"],
    "t": ["t", "7"],
    "l": ["l", "1"],
    "g": ["g", "9"],
}

MIN_LENGTH = 6
MAX_LENGTH = 20


# ─────────────────────────────────────────────────────────────
# FILE MODE — Profile format
# ─────────────────────────────────────────────────────────────

FILE_FORMAT_HELP = """
Expected profile.txt format (key: value, one per line, # = comment):

  # Basic Info
  name: John
  surname: Doe
  username: johnd
  nickname: johnny
  dob: 19900115          # YYYYMMDD or YYYY-MM-DD or DD/MM/YYYY
  email: john@email.com

  # Personal
  pet: max
  partner: jane
  child: timmy
  company: acme
  city: nairobi
  country: cameroon
  phone: 0677123456
  hobby: football

  # Extra keywords (comma-separated)
  keywords: shadow, ranger, elite2024

  # Target (optional, for notes)
  target: John Doe — ACME Corp
"""


def parse_profile_file(filepath: str) -> dict:
    """Parse a key:value profile text file into a data dict."""
    data = {}
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if ":" in line:
                    key, _, val = line.partition(":")
                    key = key.strip().lower()
                    val = val.strip()
                    if val:
                        data[key] = val
    except FileNotFoundError:
        print(f"[!] File not found: {filepath}")
        sys.exit(1)
    return data


# ─────────────────────────────────────────────────────────────
# INTERACTIVE MODE
# ─────────────────────────────────────────────────────────────

INTERACTIVE_FIELDS = [
    ("name",      "First name"),
    ("surname",   "Last name / Surname"),
    ("username",  "Username / handle"),
    ("nickname",  "Nickname / alias"),
    ("dob",       "Date of birth (any format, e.g. 19900115 / 15/01/1990)"),
    ("email",     "Email address"),
    ("phone",     "Phone number"),
    ("partner",   "Partner / spouse name"),
    ("child",     "Child's name"),
    ("pet",       "Pet name"),
    ("company",   "Company / employer"),
    ("city",      "City / hometown"),
    ("country",   "Country"),
    ("hobby",     "Hobby / interest"),
    ("keywords",  "Extra keywords (comma-separated, e.g. ranger,shadow,elite)"),
]


def interactive_mode() -> dict:
    """Prompt user for social engineering data interactively."""
    print(f"\n{'─'*55}")
    print("  Interactive Profile Builder")
    print("  Press ENTER to skip any field.")
    print(f"{'─'*55}\n")

    data = {}
    for field, label in INTERACTIVE_FIELDS:
        try:
            val = input(f"  {label}: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n[!] Aborted.")
            sys.exit(0)
        if val:
            data[field] = val

    if not data:
        print("[!] No data entered. Exiting.")
        sys.exit(0)

    return data


# ─────────────────────────────────────────────────────────────
# DATE PARSING
# ─────────────────────────────────────────────────────────────

def parse_date_variants(dob_str: str) -> list[str]:
    """Extract all useful date fragments from a DOB string."""
    digits = re.sub(r"\D", "", dob_str)
    variants = set()

    if len(digits) >= 8:
        yyyy = digits[:4]
        mm   = digits[4:6]
        dd   = digits[6:8]
        yy   = yyyy[2:]

        variants.update([
            yyyy, yy, mm, dd,
            dd + mm,
            mm + dd,
            dd + mm + yyyy,
            dd + mm + yy,
            mm + dd + yyyy,
            mm + dd + yy,
            yyyy + mm + dd,
            yy  + mm + dd,
            dd + mm,
            yyyy + mm,
        ])
    elif len(digits) == 4:
        variants.add(digits)
        variants.add(digits[2:])

    return [v for v in variants if v]


# ─────────────────────────────────────────────────────────────
# TOKEN EXTRACTION
# ─────────────────────────────────────────────────────────────

def extract_email_parts(email: str) -> list[str]:
    parts = []
    if "@" in email:
        local = email.split("@")[0]
        parts.append(local)
        # split on common separators
        for sep in [".", "_", "-"]:
            parts.extend(local.split(sep))
    return [p for p in parts if p]


def extract_phone_variants(phone: str) -> list[str]:
    digits = re.sub(r"\D", "", phone)
    variants = [digits]
    if len(digits) > 4:
        variants.append(digits[-4:])
        variants.append(digits[-6:])
    return variants


def build_base_tokens(data: dict) -> list[str]:
    """Extract all raw word tokens from profile data."""
    tokens = set()

    simple_fields = [
        "name", "surname", "username", "nickname",
        "partner", "child", "pet", "company",
        "city", "country", "hobby",
    ]
    for field in simple_fields:
        if field in data:
            val = data[field].strip()
            tokens.add(val.lower())
            tokens.add(val.capitalize())
            tokens.add(val.upper())
            # first 3 chars abbreviation
            if len(val) >= 3:
                tokens.add(val[:3].lower())

    if "dob" in data:
        tokens.update(parse_date_variants(data["dob"]))

    if "email" in data:
        for part in extract_email_parts(data["email"]):
            tokens.add(part.lower())
            tokens.add(part.capitalize())

    if "phone" in data:
        tokens.update(extract_phone_variants(data["phone"]))

    if "keywords" in data:
        for kw in data["keywords"].split(","):
            kw = kw.strip()
            if kw:
                tokens.add(kw.lower())
                tokens.add(kw.capitalize())
                tokens.add(kw.upper())

    return [t for t in tokens if t]


# ─────────────────────────────────────────────────────────────
# WORD TRANSFORMATIONS
# ─────────────────────────────────────────────────────────────

def leet_speak(word: str) -> list[str]:
    """Generate common leet-speak variants of a word."""
    word = word.lower()
    options = []
    for char in word:
        options.append(LEET_MAP.get(char, [char]))

    results = set()
    for combo in itertools.product(*options):
        results.add("".join(combo))

    return list(results - {word})   # exclude original


def case_variants(word: str) -> list[str]:
    """Return common casing variants."""
    variants = {
        word.lower(),
        word.upper(),
        word.capitalize(),
        word.title(),
        word.swapcase(),
    }
    # camelCase if word has spaces
    parts = word.split()
    if len(parts) > 1:
        variants.add(parts[0].lower() + "".join(p.capitalize() for p in parts[1:]))
    return list(variants)


def apply_suffixes_and_prefixes(word: str) -> list[str]:
    results = set()
    for suffix in COMMON_SUFFIXES:
        results.add(word + suffix)
        results.add(word.capitalize() + suffix)
    for prefix in COMMON_PREFIXES:
        if prefix:
            results.add(prefix + word)
    return list(results)


# ─────────────────────────────────────────────────────────────
# COMBINATION ENGINE (threaded)
# ─────────────────────────────────────────────────────────────

def generate_single_token_words(token: str, out_q: queue.Queue):
    """All variants for a single token."""
    words = set()

    for cv in case_variants(token):
        words.add(cv)
        for w in apply_suffixes_and_prefixes(cv):
            words.add(w)

    for lv in leet_speak(token):
        words.add(lv)
        for w in apply_suffixes_and_prefixes(lv):
            words.add(w)

    for sc in SPECIAL_CHARS:
        words.add(token + sc)
        words.add(sc + token)
        words.add(token.capitalize() + sc)

    for item in words:
        out_q.put(item)


def generate_two_token_combos(t1: str, t2: str, out_q: queue.Queue):
    """Combine two tokens in various ways."""
    words = set()
    separators = ["", "_", ".", "-", "@", "!", "#"]

    for sep in separators:
        combos = [
            t1 + sep + t2,
            t2 + sep + t1,
            t1.capitalize() + sep + t2,
            t1 + sep + t2.capitalize(),
            t1.capitalize() + sep + t2.capitalize(),
            t1.upper() + sep + t2,
            t1 + sep + t2.upper(),
        ]
        words.update(combos)

    # with suffixes on combined
    for w in list(words):
        for suffix in COMMON_SUFFIXES[:10]:   # limit explosion
            words.add(w + suffix)

    for item in words:
        out_q.put(item)


def generate_three_token_combos(tokens: list[str], out_q: queue.Queue):
    """Three-token combinations (more targeted)."""
    words = set()
    for t1, t2, t3 in itertools.permutations(tokens[:6], 3):
        for sep in ["", "_", ".", "-"]:
            words.add(t1 + sep + t2 + sep + t3)
            words.add(t1.capitalize() + sep + t2 + sep + t3)
    for item in words:
        out_q.put(item)


def generate_wordlist(data: dict, threads: int = 8) -> set[str]:
    """Main generation engine using a thread pool."""

    print("\n[*] Extracting tokens from profile data...")
    tokens = build_base_tokens(data)
    print(f"[+] {len(tokens)} base tokens extracted.")

    out_q  = queue.Queue()
    results = set()

    print(f"[*] Generating wordlist using {threads} threads...")
    t_start = time.time()

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = []

        # Single-token jobs
        for token in tokens:
            futures.append(
                executor.submit(generate_single_token_words, token, out_q)
            )

        # Two-token combo jobs
        token_list = list(tokens)
        for t1, t2 in itertools.combinations(token_list, 2):
            futures.append(
                executor.submit(generate_two_token_combos, t1, t2, out_q)
            )

        # Three-token combos (capped to avoid explosion)
        if len(token_list) <= 10:
            futures.append(
                executor.submit(generate_three_token_combos, token_list, out_q)
            )

        for f in as_completed(futures):
            pass   # drain futures

    # Drain queue
    while not out_q.empty():
        results.add(out_q.get())

    # Filter by length
    before = len(results)
    results = {w for w in results if MIN_LENGTH <= len(w) <= MAX_LENGTH}

    t_end = time.time()
    print(f"[+] Generated {before:,} candidates, "
          f"{len(results):,} after length filter ({MIN_LENGTH}–{MAX_LENGTH} chars).")
    print(f"[+] Generation time: {t_end - t_start:.2f}s")

    return results


# ─────────────────────────────────────────────────────────────
# OUTPUT
# ─────────────────────────────────────────────────────────────

def save_wordlist(words: set[str], output_path: str):
    sorted_words = sorted(words, key=lambda w: (len(w), w))
    with open(output_path, "w", encoding="utf-8") as f:
        for word in sorted_words:
            f.write(word + "\n")
    print(f"[+] Wordlist saved → {output_path}  ({len(sorted_words):,} entries)")


def default_output_name(data: dict) -> str:
    name = data.get("name", data.get("username", "target"))
    name = re.sub(r"\W+", "_", name.lower())
    ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"{name}_wordlist_{ts}.txt"


# ─────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="OSINT Wordlist Generator — Penetration Testing Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=FILE_FORMAT_HELP,
    )

    mode = p.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "-f", "--file",
        metavar="PROFILE.TXT",
        help="Path to a structured profile text file (key: value format).",
    )
    mode.add_argument(
        "-i", "--interactive",
        action="store_true",
        help="Interactive mode — enter profile data step by step.",
    )

    p.add_argument(
        "-o", "--output",
        metavar="OUTPUT.TXT",
        help="Output file path. Auto-generated if omitted.",
    )
    p.add_argument(
        "-t", "--threads",
        type=int,
        default=8,
        metavar="N",
        help="Number of worker threads (default: 8).",
    )
    p.add_argument(
        "--min-len",
        type=int,
        default=6,
        metavar="N",
        help="Minimum password length to include (default: 6).",
    )
    p.add_argument(
        "--max-len",
        type=int,
        default=20,
        metavar="N",
        help="Maximum password length to include (default: 20).",
    )
    p.add_argument(
        "--show-format",
        action="store_true",
        help="Print the expected profile file format and exit.",
    )
    return p


# ─────────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────────

def main():
    print(BANNER)

    parser = build_parser()
    args   = parser.parse_args()

    if args.show_format:
        print(FILE_FORMAT_HELP)
        sys.exit(0)

    # Apply length settings
    global MIN_LENGTH, MAX_LENGTH
    MIN_LENGTH = args.min_len
    MAX_LENGTH = args.max_len

    # Load data
    if args.file:
        print(f"[*] Loading profile from: {args.file}")
        data = parse_profile_file(args.file)
        print(f"[+] {len(data)} fields loaded.")
    else:
        data = interactive_mode()
        print(f"\n[+] {len(data)} fields collected.")

    # Determine output path
    output = args.output or default_output_name(data)

    # Generate
    words = generate_wordlist(data, threads=args.threads)

    # Save
    save_wordlist(words, output)

    print("\n[✓] Done. Use responsibly on authorized targets only.\n")


if __name__ == "__main__":
    main()
