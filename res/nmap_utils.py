import sys, os
from PyQt6.QtCore import QProcess, QIODevice, QTemporaryFile

script_name = os.path.basename(sys.modules['__main__'].__file__)
script_dir = os.path.abspath(os.path.dirname(sys.modules['__main__'].__file__))


class NmapProcess:
    def __init__(self, command_entry, output_filename, stdout_callback=None, stderr_callback=None,
                 finished_callback=None, generate_html=False, from_cli=False, parent=None):
        self.command_entry = command_entry
        self.output_filename = output_filename
        self.process = QProcess(parent)
        self.stdout_callback = stdout_callback
        self.stderr_callback = stderr_callback
        self.finished_callback = finished_callback
        self.generate_html = generate_html
        self.from_cli = from_cli
        self.searchsploit_process = None

    def handle_stdout(self):
        data = self.process.readAllStandardOutput().data().decode()
        if self.stdout_callback:
            self.stdout_callback(data, sender=self.process)

    def handle_stderr(self):
        data = self.process.readAllStandardError().data().decode()
        if self.stderr_callback:
            self.stderr_callback(data, sender=self.process)

    def kill(self):
        if self.process:
            self.process.kill()

    def run(self):
        nmap_output_file = QTemporaryFile("XXXXXX_nmap_output.xml")
        nmap_output_file.setAutoRemove(False)
        if not nmap_output_file.open(QIODevice.OpenModeFlag.ReadWrite | QIODevice.OpenModeFlag.Text):
            print("Could not open nmap output file")
            return

        if self.output_filename is not None:
            self.output_xml = self.output_filename
        else:
            self.output_xml = nmap_output_file.fileName()

        print(self.command_entry)
        args = custom_split(self.command_entry)
        args = args[1:]  # Remove the first argument
        args = [arg.replace('"', '') for arg in strip_output_flags(args)]

        # Check if --script argument is present
        script_arg_index = -1
        for i, arg in enumerate(args):
            if arg == '--script':
                script_arg_index = i
                break

        # If --script is present, check the next argument and prepend the absolute path if necessary
        if script_arg_index != -1 and script_arg_index + 1 < len(args):
            next_arg = args[script_arg_index + 1]
            if next_arg.startswith("scripts/"):
                args[script_arg_index + 1] = os.path.join(script_dir, next_arg)

        self.process = QProcess()
        if self.stdout_callback:
            self.process.readyReadStandardOutput.connect(self.handle_stdout)
        if self.stderr_callback:
            self.process.readyReadStandardError.connect(self.handle_stderr)
        if self.finished_callback:
            self.process.finished.connect(lambda: self.finished_callback(self.output_filename, self.output_xml, self.generate_html, sender=self.process))

        nmap_command = ["nmap", ["-oX", self.output_xml] + args]
        self.process.start(*nmap_command)
        print(f"sent cmd:\tnmap {' '.join(nmap_command[1])}")
        if self.from_cli:
            self.process.waitForFinished(-1)


def remove_argument(arguments, arg_to_remove):
    new_arguments = []
    i = 0
    while i < len(arguments):
        arg = arguments[i]
        if arg != arg_to_remove:
            new_arguments.append(arg)
        else:
            # Check if the next word does not start with '-' and is not the last word in the command
            if i < len(arguments) - 1 and not arguments[i + 1].startswith('-'):
                i += 1  # Skip the next word
        i += 1
    return new_arguments


def strip_output_flags(command_list):
    output_flags = {"-oX", "-oA"}
    new_command_list = []
    i = 0
    while i < len(command_list):
        arg = command_list[i]
        if arg not in output_flags:
            new_command_list.append(arg)
        else:
            # Skip the next argument if it's a single dash or doesn't start with a dash
            if i < len(command_list) - 1 and (command_list[i + 1] == '-' or not command_list[i + 1].startswith('-')):
                i += 1
        i += 1
    return new_command_list


def custom_split(command):
    args = []
    current_arg = ""
    inside_quotes = False
    inside_parentheses = 0
    quote_flag = False

    for char in command:
        if char == '"' and not inside_parentheses:
            inside_quotes = not inside_quotes
            quote_flag = not quote_flag
            if inside_quotes:  # Add the opening quote directly
                current_arg += char
            else:  # Add the closing quote directly
                current_arg += char
        elif char == '(' and not inside_quotes:
            inside_parentheses += 1
        elif char == ')' and not inside_quotes:
            inside_parentheses -= 1
        elif char == ' ' and not inside_quotes and inside_parentheses == 0:
            args.append(current_arg)
            current_arg = ""
            quote_flag = False
        else:
            current_arg += char

    if current_arg:
        args.append(current_arg)

    return args


def setup_profiles(self):

    self.profile_and_script_details = {
        "Zenmap default profiles": {
            "Intense scan": {"nmap_args": "-T4 -A -v"},
            "Intense scan plus UDP": {"nmap_args": "-sS -sU -T4 -A -v"},
            "Intense scan, all TCP ports": {"nmap_args": "-p 1-65535 -T4 -A -v"},
            "Intense scan, no ping": {"nmap_args": "-T4 -A -v -Pn"},
            "Ping scan": {"nmap_args": "-sn"},
            "Quick scan": {"nmap_args": "-T4 -F"},
            "Quick scan plus": {"nmap_args": "-sV -T4 -O -F --version-light"},
            "Quick traceroute": {"nmap_args": "-sn --traceroute"},
            "Regular scan": {"nmap_args": ""},
            "Slow comprehensive scan": {"nmap_args": "-sS -sU -T4 -A -v -PE -PP -PS80,443 -PA3389 -PU40125 -PY -g 53 --script \"default or (discovery and safe)\""},
        },
        "NextGeNmap developer profiles": {
            "quip scan plus": {"nmap_args": "-sS -sV -T5 -O -vv -n --version-intensity 0 --min-parallelism 4 --initial-rtt-timeout 250ms"},
            "quip scan uber": {"nmap_args": "-sS -sV -T5 -O -vv -n --version-intensity 0 --max-rtt-timeout 300ms --max-retries 2 --max-scan-delay 10ms --min-rate 1000 --script scripts/vulscan,scripts/http-vulners-regex,scripts/vulners --script-args mincvss=8.0"},
            "Quick OS Detection Scan": {"nmap_args": "-sS -T5 -O --max-rtt-timeout 300ms --min-rate 1000"},
            "Aggressive UDP Scan": {"nmap_args": "-sU -T5 --max-rtt-timeout 300ms --min-rate 1000"},
            "Fast Top 100 Ports Scan": {"nmap_args": "-p- -T5 --max-rtt-timeout 300ms --min-rate 1000"},
        },
        "scip AG Scripts": {
            "vulscan": {"nmap_args": "--script scripts/vulscan.nse", "script_args": ""},
            "httprecon": {"nmap_args": "--script scripts/httprecon.nse", "script_args": "httprecontoplist=20"},
        },
        "vulnersCom Scripts": {
            "vulners": {"nmap_args": "--script scripts/http-vulners-regex,scripts/vulners", "script_args": "mincvss=7.5"},
            "http-vulners-regex": {"nmap_args": "--script scripts/http-vulners-regex", "script_args": 'paths=http-vulners-paths.txt'},
        },
        "nccgroup Scripts": {
            "21nails": {"nmap_args": "--script scripts/smtp-vuln-cve2020-28017-through-28026-21nails", "script_args": ""},
            "pjl-info-config": {"nmap_args": "--script scripts/pjl-info-config", "script_args": ""},
            "http-lexmark-version": {"nmap_args": "--script scripts/http-lexmark-version", "script_args": ""},
        },
        "NextgeNmap curated scripts": {
            "EternalBlue scan": {"nmap_args": "-p 445 --script smb-vuln-ms17-010"},
            "Heartbleed scan": {"nmap_args": "-p 443 --script ssl-heartbleed"},
            "Shellshock Vulnerability Scan": {"nmap_args": "-p 80,443 --script http-shellshock"},
            "Ghost Vulnerability Scan": {"nmap_args": "-p 80,443 --script http-ghost"},
            "Poodle SSLv3 Vulnerability Scan": {"nmap_args": "-p 443 --script ssl-poodle"},
            "DROWN Vulnerability Scan": {"nmap_args": "-p 443 --script sslv2-drown"},
            "WannaCry Ransomware Scan": {"nmap_args": "-p 445 --script smb-vuln-ms17-010"},
            "Common web vulnerabilities scan": {"nmap_args": "-p 80,443 --script http-enum,http-vuln-*"},
            "Drupal vulnerability scan": {"nmap_args": "-p 80,443 --script http-drupal-enum,http-drupal-enum-users"},
            "WordPress vulnerability scan": {"nmap_args": "-p 80,443 --script http-wordpress-enum,http-wordpress-brute,http-wordpress-plugins"},
            "Joomla vulnerability scan": {"nmap_args": "-p 80,443 --script http-joomla-enum-users,http-joomla-enum-config,http-joomla-brute"},
            "SMB vulnerabilities scan": {"nmap_args": "-p 139,445 --script smb-vuln*"},
            "SSL/TLS vulnerabilities scan": {"nmap_args": "-p 443 --script ssl-enum-ciphers,ssl-known-key,ssl-cert-intaddr,sslccs-injection,sslv2-drown,sslv2"},
            "DNS zone transfer scan": {"nmap_args": "-p 53 --script dns-zone-transfer --script-args dns-zone-transfer.domain=example.com"},
            "SNMP vulnerabilities scan": {"nmap_args": "-p 161 --script snmp-vuln*"},
            "NTP DDoS amplification scan": {"nmap_args": "-p 123 --script ntp-monlist"},
            "Mail servers vulnerabilities scan": {"nmap_args": "-p 25,110,143,465,587,993,995 --script smtp-vuln*,pop3-vuln*,imap-vuln*"},
            "Brute force FTP login": {"nmap_args": "-p 21 --script ftp-brute"},
            "Brute force SSH login": {"nmap_args": "-p 22 --script ssh-brute"},
            "Brute force Telnet login": {"nmap_args": "-p 23 --script telnet-brute"},
            "Brute force RDP login": {"nmap_args": "-p 3389 --script rdp-ntlm-info,rdp-vuln-ms12-020"},
            "Brute force HTTP login": {"nmap_args": "-p 80,443 --script http-form-brute,http-get,http-post"},
            "ALL scripts matching \"vuln\" category": {"nmap_args": "-sV --version-intensity 5 --script vuln"},
        },
    }


highlight_rules = {  # thank you Zenmap for the regexes ~
    "date": {
        "bold": True,
        "italic": False,
        "underline": False,
        "text": [0, 0, 0],
        "highlight": [65535, 65535, 65535],
        "regex": r"\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}\s.{1,4}"},
    "hostname": {
        "bold": True,
        "italic": True,
        "underline": True,
        "text": [0, 111, 65535],
        "highlight": [65535, 65535, 65535],
        "regex": r"(\w{2,}://)*[\w-]+(\.[\w-]+)+"},
    "ip": {
        "bold": True,
        "italic": False,
        "underline": False,
        "text": [0, 0, 0],
        "highlight": [65535, 65535, 65535],
        "regex": r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"},
    "port_list": {
        "bold": True,
        "italic": False,
        "underline": False,
        "text": [0, 1272, 28362],
        "highlight": [65535, 65535, 65535],
        "regex": r"PORT\s+STATE\s+SERVICE(\s+VERSION)?[^\n]*"},
    "open_port": {
        "bold": True,
        "italic": False,
        "underline": False,
        "text": [0, 41036, 2396],
        "highlight": [65535, 65535, 65535],
        "regex": r"\d{1,5}/.{1,5}\s+open\s+.*"},
    "closed_port": {
        "bold": False,
        "italic": False,
        "underline": False,
        "text": [65535, 0, 0],
        "highlight": [65535, 65535, 65535],
        "regex": r"\d{1,5}/.{1,5}\s+closed\s+.*"},
    "filtered_port": {
        "bold": False,
        "italic": False,
        "underline": False,
        "text": [38502, 39119, 0],
        "highlight": [65535, 65535, 65535],
        "regex": r"\d{1,5}/.{1,5}\s+filtered\s+.*"},
    "details": {
        "bold": True,
        "italic": False,
        "underline": True,
        "text": [0, 0, 0],
        "highlight": [65535, 65535, 65535],
        "regex": r"^(\w{2,}[\s]{,3}){,4}:"}
}


exclude_args_dict = {
    ("-p", "--port"): None,
    ("--exclude-ports",): None,
    ("-S", "--source-ip"): None,
    ("-g", "--source-port"): None,
    ("-D", "--decoy"): None,
    ("-e", "--interface"): None,
    ("-r", "--non-randomize-ports"): None,
    ("-iL", "--input-filename"): None,
    ("-iR", "--random-targets"): None,
    ("-sI", "--idle-scan"): None,
    ("--script",): None,
    ("--script-args",): None,
    ("--script-args-file",): None,
    ("--script-trace",): None,
    ("--script-updatedb",): None,
    ("--stylesheet",): None,
    ("-oA", "--output-all-formats"): None,
    ("-oX", "--output-xml"): None,
    ("-oN", "--output-normal"): None,
    ("-oS", "--output-skiddie"): None,
    ("-oG", "--output-grepable"): None,
    ("--exclude",): None,
    ("--excludefile",): None,
    ("--max-retries",): None,
    ("--host-timeout",): None,
    ("--scan-delay",): None,
    ("--max-scan-delay",): None,
    ("--min-rate",): None,
    ("--max-rate",): None,
    ("--min-parallelism",): None,
    ("--max-parallelism",): None,
    ("--min-hostgroup",): None,
    ("--max-hostgroup",): None,
    ("--min-rtt-timeout",): None,
    ("--max-rtt-timeout",): None,
    ("--initial-rtt-timeout",): None,
    ("--stats-every",): None,
    ("--ttl",): None,
    ("--spoof-mac",): None,
    ("--version-intensity",): None,
    ("and",): None,
    ("or",): None,
    ("not",): None,
    ("  ",): None,
}
