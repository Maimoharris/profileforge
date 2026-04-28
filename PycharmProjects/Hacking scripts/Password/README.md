# OSINT Wordlist Generator

```
  ___  ___ ___ _  _ _____   __  _____ ___ _  _
 / _ \/ __|_ _| \| |_   _| |\ \/ / __| __| \| |
| (_) \__ \| || .` | | |   | >  <| (_ | _|| .` |
 \___/|___/___|_|\_| |_|  |_/_/\_\___|___|_|\_|

         OSINT Wordlist Generator v1.0
```

A fast, threaded password wordlist generator built for **authorized penetration testing and red team engagements**. Generate targeted password candidates from social engineering / OSINT data — names, dates of birth, usernames, relationships, and more.

> ⚠️ **For authorized use only.** Only use this tool against systems and accounts you have explicit written permission to test. Unauthorized use is illegal.

---

## Features

- **Two input modes** — file-based (structured `.txt` profile) or fully interactive CLI
- **Threaded generation** — concurrent workers for high-speed wordlist building
- **Leet speak variants** — `shadow` → `$h4d0w`, `5h@dow`, `5hadow`, etc.
- **Case mutations** — lowercase, UPPERCASE, Capitalize, Title Case, sWaPcAsE
- **Date-of-birth parsing** — any format → extracts `dd`, `mm`, `yyyy`, `yy`, `ddmmyyyy`, `mmddyy`, etc.
- **Email decomposition** — splits `john.doe@gmail.com` into `john`, `doe`, `johndoe`
- **Two-token & three-token combos** — `john_doe`, `doe.1990`, `shadow_acme_2024`
- **Special character injection** — appended, prepended, and embedded (`!`, `@`, `#`, `$`, `_`, etc.)
- **Common suffixes & prefixes** — `123`, `!`, `2024`, `007`, `00`, `@`, `!@#`, etc.
- **Length filtering** — configurable `--min-len` / `--max-len` flags
- **Auto output naming** — `john_wordlist_20250428_143021.txt` when no `-o` given

---

## Requirements

- Python 3.10+
- No third-party dependencies — standard library only

---

## Installation

```bash
git clone https://github.com/yourusername/osint-wordlist-gen.git
cd osint-wordlist-gen
chmod +x wordlist_gen.py
```

---

## Usage

### Mode 1 — File Mode

Feed a structured profile `.txt` file:

```bash
python3 wordlist_gen.py -f profile.txt -o wordlist.txt
```

### Mode 2 — Interactive Mode

Enter data step by step at runtime. Press `ENTER` to skip any field:

```bash
python3 wordlist_gen.py -i -o wordlist.txt
```

---

## Profile File Format

Create a plain `.txt` file with `key: value` pairs. Lines starting with `#` are comments and are ignored. All fields are **optional**.

```
# Basic identity
name: john
surname: doe
username: johndoe
nickname: johnny

# Date of birth (any common format works)
dob: 19900115

# Contact info
email: johndoe@gmail.com
phone: 0677123456

# Relationships
partner: jane
child: timmy
pet: max

# Work & location
company: acme
city: nairobi
country: kenya

# Interests
hobby: football

# Extra OSINT keywords (comma-separated)
keywords: shadow, ranger, elite, boss2024
```

Print format help at any time:

```bash
python3 wordlist_gen.py --show-format
```

---

## All Options

```
usage: wordlist_gen.py [-h] (-f PROFILE.TXT | -i) [-o OUTPUT.TXT]
                       [-t N] [--min-len N] [--max-len N] [--show-format]

options:
  -f, --file       Path to a structured profile .txt file
  -i, --interactive  Interactive mode — enter data step by step
  -o, --output     Output file path (auto-generated if omitted)
  -t, --threads    Number of worker threads (default: 8)
  --min-len        Minimum password length to include (default: 6)
  --max-len        Maximum password length to include (default: 20)
  --show-format    Print the expected profile file format and exit
```

### Examples

```bash
# Basic file mode
python3 wordlist_gen.py -f target.txt -o wordlist.txt

# Interactive with custom length filter and thread count
python3 wordlist_gen.py -i --min-len 8 --max-len 16 --threads 16

# File mode with tight length constraints
python3 wordlist_gen.py -f target.txt --min-len 8 --max-len 12 -o out.txt

# Print profile format reference
python3 wordlist_gen.py --show-format
```

---

## Performance

| Profile fields | Base tokens | Candidates | Time (8 threads) |
|---|---|---|---|
| 5 fields | ~25 tokens | ~80,000 | ~8s |
| 10 fields | ~45 tokens | ~200,000 | ~18s |
| 16 fields | ~68 tokens | ~397,000 | ~32s |

Increase `--threads` on multi-core machines for faster generation.

---

## How It Works

```
Profile Data (file or interactive)
        │
        ▼
  Token Extraction
  ┌─────────────────────────────────────────┐
  │  name / surname / username / nickname   │
  │  DOB fragments (dd, mm, yyyy, yy, ...)  │
  │  Email parts / phone variants           │
  │  Keywords / company / city / pet ...    │
  └─────────────────────────────────────────┘
        │
        ▼
  Word Generation (threaded)
  ┌───────────────────┐  ┌──────────────────────┐  ┌───────────────────────┐
  │  Single-token     │  │  Two-token combos     │  │  Three-token combos   │
  │  • case variants  │  │  john_doe             │  │  john_doe_1990        │
  │  • leet speak     │  │  doe.1990             │  │  max_jane_acme        │
  │  • suffixes       │  │  shadow@acme          │  │  ranger_shadow_2024   │
  │  • special chars  │  │  + suffixes           │  │                       │
  └───────────────────┘  └──────────────────────┘  └───────────────────────┘
        │
        ▼
  Length Filter (min/max)
        │
        ▼
  Sorted Wordlist → output.txt
```

---

## Output

The output is a plain `.txt` file, one password candidate per line, sorted by length then alphabetically. Compatible with tools like **Hydra**, **Medusa**, **Hashcat**, and **John the Ripper**.

```bash
# Example: use with Hydra for SSH
hydra -l admin -P wordlist.txt ssh://192.168.1.1

# Example: use with Hashcat (dictionary attack)
hashcat -m 0 hashes.txt wordlist.txt

# Example: use with John
john --wordlist=wordlist.txt hashes.txt
```

---

## Legal Disclaimer

This tool is intended **strictly for authorized security testing** including:

- Penetration tests with written scope agreements
- Red team engagements
- CTF competitions
- Personal/lab environments you own

Using this tool against systems or accounts without explicit written authorization is **illegal** and may violate laws including the Computer Fraud and Abuse Act (CFAA), the UK Computer Misuse Act, and similar legislation in your jurisdiction.

**The author assumes no liability for misuse.**

---

## Contributing

Pull requests are welcome. For major changes, open an issue first.

1. Fork the repo
2. Create a feature branch (`git checkout -b feature/your-feature`)
3. Commit your changes
4. Push and open a PR

---

## License

MIT License — see [LICENSE](LICENSE) for details.
