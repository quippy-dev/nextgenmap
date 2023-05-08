# NextgeNmap

NextgeNmap is a comprehensive cross-platform GUI for Nmap with deep integrations for SearchSploit, vulscan, and other vulnerability detection scripts and programs. Schedule automated scans, set up email alerts when customizable criteria are met, and generate beautiful HTML visualizations of the Nmap reports. With a sleek user interface and extensive documentation, NextgeNmap is designed to streamline and enhance the network scanning experience.


## Features

- Cross-platform Nmap GUI built using Python 3 and PyQt 6.5
- Pre-defined profiles for efficient and targeted scanning
- Integration with community scripts and vulnerability detection tools
- Automated scan scheduling with customizable criteria
- Email alerts for scan results
- Visually appealing HTML reports generated with an XSLT parser
- Extensive documentation, including profiles, scripts, options, flags, and a glossary

![image](https://user-images.githubusercontent.com/131914530/236519376-5a7f890c-0b3a-4ba1-b940-038af263d8f9.png)

## Installation

**1. Ensure nmap is in your PATH so that it can be executed from anywhere:**

*For Windows:*

- Locate the folder where nmap.exe is installed, typically:
  ```
  C:\Program Files (x86)\Nmap\
  ```
- Press the Windows key and search for 'Environment Variables'.
- Click on 'Edit the system environment variables'.
- Click on 'Environment Variables...' in the System Properties window.
- Under 'System variables', find 'Path' and click 'Edit...'.
- Click 'New', and then add the path to the Nmap folder (e.g., `C:\Program Files (x86)\Nmap\`).
- Click 'OK' to save the changes.

*For Linux:*

- Ensure Nmap is installed and available system-wide. This is usually the default behavior when installing Nmap using a package manager like `apt`, `yum`, or `pacman`.
- If Nmap is installed locally or in a non-standard location, add the Nmap folder to your PATH in your shell configuration file (e.g., `~/.bashrc`, `~/.zshrc`):

  ```
  export PATH=$PATH:/path/to/nmap-folder
  ```
- Save the file and restart your terminal or run `source ~/.bashrc` (or the appropriate configuration file) to apply the changes.
---

**2. Clone the repository:**

```bash
git clone https://github.com/quippy-dev/nextgenmap.git
```

**3. Navigate to the project directory:**

```bash
cd nextgenmap
```

**4. Install the required packages:**

```bash
pip install -r requirements.txt
```

## Usage

Launch NextgeNmap with the following command:

```bash
python3 .\nextgenmap.py
```

![image](https://user-images.githubusercontent.com/131914530/236517197-89e1eeec-858c-4e77-9100-b2dd5f18a86b.png)

## Contributing

We welcome contributions from the community! If you'd like to contribute, please follow these steps:

1. Fork the repository
2. Create a new branch with your changes
3. Submit a pull request for review

## License

NextgeNmap is released under the [GPLv3 license](./LICENSE). All community project integrations are credited, linked, and GPL/Creative Commons licenses provided.

## Acknowledgements

We would like to express our gratitude to GitHub Copilot and OpenAI's GPT-4 for their invaluable assistance throughout the development process. While their guidance and suggestions undoubtedly made our work smoother and more efficient, we want to emphasize that the entire codebase was created from scratch by our team.

GitHub Copilot and GPT-4 played a crucial role in providing inspiration, addressing questions, and suggesting solutions, which enabled us to develop a powerful and versatile tool. Their AI-driven expertise allowed us to explore the potential of our solution and contribute a valuable resource to the community. However, it is our team's hard work, dedication, and creativity that have ultimately shaped NextgeNmap into the innovative project it is today.