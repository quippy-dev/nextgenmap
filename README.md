# NextgeNmap

Security-first Nmap automation GUI built for SecOps and systems teams that need repeatable scans, low noise, and fast reporting. NextgeNmap wraps Nmap with curated profiles, scheduling, SearchSploit integration, and HTML reporting so routine reconnaissance feels like a product, not a pile of scripts.


## Features

- Cross-platform desktop app (Python 3 + PyQt 6.5) with a native-feeling GUI
- Curated scan profiles for consistent, targeted recon without rewriting flags
- Hooks for community scripts (SearchSploit, vulscan, and related checks)
- Automated scheduling with customizable criteria and email notifications
- HTML report generation via XSLT for stakeholder-ready output
- Reference docs covering profiles, scripts, options, flags, and a glossary

![image](https://user-images.githubusercontent.com/131914530/236519376-5a7f890c-0b3a-4ba1-b940-038af263d8f9.png)

## Prerequisites

**All platforms**
- Python 3.10+ available as `python3`/`python`
- Nmap CLI installed and on your PATH

**macOS**
- Homebrew recommended: `brew install nmap exploitdb`
- If prompted for build tools when installing Python packages: `xcode-select --install`

**Windows**

- Install Nmap (7.94+). Add `C:\Program Files (x86)\Nmap\` (or your install path) to PATH via *Edit the system environment variables* → *Environment Variables* → *Path* → *New*.
- Install Python 3.11+ (64-bit) and ensure `python` is in PATH.

**Linux**
- Use your package manager (examples): `sudo apt install nmap python3 python3-venv` or `sudo dnf install nmap python3 python3-virtualenv`.

## Installation

**1. Clone the repository:**

```bash
git clone https://github.com/quippy-dev/nextgenmap.git
```

**2. Navigate to the project directory:**

```bash
cd nextgenmap
```

**3. Install the required packages:**

```bash
pip install -r requirements.txt
```

Optionally, install in editable mode (src layout):

```bash
pip install -e .
```

## Usage

Launch NextgeNmap with one of the following commands:

```bash
python3 ./nextgenmap.py
python3 -m nextgenmap
```

![image](https://user-images.githubusercontent.com/131914530/236517197-89e1eeec-858c-4e77-9100-b2dd5f18a86b.png)

## SearchSploit integration

- NextgeNmap auto-detects SearchSploit on macOS (Homebrew `exploitdb`), Linux, and Windows.
- Preferred order: `SEARCHSPLOIT_PATH` env var, binaries on your `PATH`, common Homebrew locations, and finally Windows WSL (`wsl -e searchsploit`).
- On Windows, set `SEARCHSPLOIT_WSL_DISTRO=<name>` to target a specific distribution when falling back to WSL.

## Testing

Install dev/test dependencies:

```bash
pip install -r requirements-dev.txt
```

Run the tests:

```bash
pytest -q
```

## Contributing

We welcome contributions from the community! If you'd like to contribute, please follow these steps:

1. Fork the repository
2. Create a new branch with your changes
3. Submit a pull request for review

## License

NextgeNmap is released under the [GPLv3 license](./LICENSE). All community project integrations are credited, linked, and GPL/Creative Commons licenses provided.

## Legal Disclaimer

Usage of NextgeNmap for attacking targets without prior mutual consent is illegal. You are responsible for complying with all applicable laws. The developers assume no liability and are not responsible for misuse or damage caused by this program.
