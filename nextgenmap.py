import sys, os, tempfile, shlex, re, argparse, subprocess, psutil
from math import floor
from nmap import PortScanner, PortScannerError
from crontab import CronTab
from PyQt6.QtWidgets import QApplication, QMainWindow, QStyleFactory, QTableWidgetItem, QDialog, QPushButton
from PyQt6.QtCore import Qt, QProcess, QThread, pyqtSignal 
from PyQt6.QtGui import QTextCursor, QTextOption, QStandardItemModel, QStandardItem, QColor, QTextCharFormat, QFont, QFontDatabase
from PyQt6.uic import loadUi


class NmapProcess:
    def __init__(self, command_entry, output_file, stdout_callback=None, stderr_callback=None, finished_callback=None, parent=None, from_cli=False):
        self.command_entry = command_entry
        self.output_file = output_file
        self.process = None
        self.stdout_callback = stdout_callback
        self.stderr_callback = stderr_callback
        self.finished_callback = finished_callback
        self.from_cli = from_cli

    def handle_stdout(self):
        data = self.process.readAllStandardOutput().data().decode()
        if self.stdout_callback:
            self.stdout_callback(data, sender=self.process)

    def handle_stderr(self):
        data = self.process.readAllStandardError().data().decode()
        if self.stderr_callback:
            self.stderr_callback(data, sender=self.process)

    def terminate(self):
        if self.process:
            self.process.terminate()

    def run(self):
        with tempfile.NamedTemporaryFile(delete=False) as temp_xml:
            self.output_xml = temp_xml.name
        args = shlex.split(self.command_entry)
        print (args)
        args[-1:-1] = ["-oX", self.output_xml]
        print (args)
        
        self.process = QProcess()
        if self.stdout_callback:
            self.process.readyReadStandardOutput.connect(self.handle_stdout)
        if self.stderr_callback:
            self.process.readyReadStandardError.connect(self.handle_stderr)
        if self.finished_callback:
            self.process.finished.connect(lambda: self.finished_callback(self.output_file, self.output_xml, sender=self.process))
            #self.process.finished.connect(lambda: self.finished_callback(self.output_xml, sender=self.process))

        self.process.start(args[0], args[1:])

        if self.from_cli:
            self.process.waitForFinished(-1)


class SeparatorStandardItemModel(QStandardItemModel):
    def flags(self, index):
        if self.itemFromIndex(index).data(Qt.ItemDataRole.UserRole) == "separator":
            return Qt.ItemFlag.NoItemFlags
        return super().flags(index)


class VulnResultsDialog(QDialog):
    def __init__(self, parent=None, main_window=None):
        super().__init__(parent)
        loadUi('vuln_dialog.ui', self)
        self.main_window = main_window
        self.init_ui()

    def init_ui(self):
        print("VulnResultsDialog init_ui")


class SchedulerDialog(QDialog):
    def __init__(self, parent=None, main_window=None):
        super().__init__(parent)
        loadUi('scheduler_dialog.ui', self)
        self.main_window = main_window
        self.updating_cron_schedule = False
        self.toggling_custom_radio = False
        self.init_ui()
        if parent is not None:
            self.buttonBox.accepted.connect(parent.schedule_scan) 
        self.buttonBox.rejected.connect(self.reject)

    def init_ui(self):
        self.cboxes = [self.min_cbox, self.hour_cbox, self.date_cbox, self.month_cbox, self.day_cbox]
        cbox_labels = [["Minute"] + [str(i) for i in range(0, 60)],
                    ["Hour"] + [str(i) for i in range(0, 24)],
                    ["Date"] + [str(i) for i in range(1, 32)],
                    ["Month"] + ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Nov", "Dec"],
                    ["Day"] + ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"]]
        for cbox, labels in zip(self.cboxes, cbox_labels):
            cbox.addItems(labels)
            cbox.setCurrentIndex(0)

        self.cron_schedule.document().setDefaultTextOption(QTextOption(Qt.AlignmentFlag.AlignCenter))
        for radio in [self.hourly_radio, self.daily_radio, self.weekly_radio, self.custom_radio]:
            radio.toggled.connect(self.update_cron_schedule)
        for cbox in self.cboxes:
            cbox.currentIndexChanged.connect(self.update_cron_schedule)
        self.cron_schedule.textChanged.connect(self.parse_cron_schedule)
        self.sender_has_focus = False
        self.update_cron_schedule()

    def update_cbox_states(self, cron_text, cb_states, cb_indices):
        for i, part in enumerate(cron_text.split()):
            cb_states[i] = not any(c in part for c in ',/-')
            cb_indices[i] = int(part) + 1 if part.isdigit() else 0

    def parse_cron_schedule(self):
        guru_format = f"https://crontab.guru/{self.cron_schedule.toPlainText().replace(' ', '_')}"
        self.guru_link.setText(f'<a href="{guru_format}"><span style="text-decoration:none;color:#007BFF;">{guru_format}</span></a>')

        if self.updating_cron_schedule:
            return

        cron_text = self.cron_schedule.toPlainText().strip()
        cron_pattern = re.compile(r'^(\*|\d+|\d+-\d+|\*/\d+|\d+(,\d+)*)( (\*|\d+|\d+-\d+|\*/\d+|\d+(,\d+)*)){4}$')
        if not cron_pattern.match(cron_text):
            return

        self.sender_has_focus = self.sender() and self.sender().hasFocus()
        if self.sender_has_focus:
            self.custom_radio.setChecked(True)

        cb_states = [True] * 5
        cb_indices = [0] * 5
        self.update_cbox_states(cron_text, cb_states, cb_indices)

        for cb, state, index in zip(self.cboxes, cb_states, cb_indices):
            cb.setEnabled(state)
            cb.setCurrentIndex(index)
        self.sender_has_focus = False

    def update_cron_schedule(self):
        if self.sender() == self.cron_schedule or self.sender_has_focus:
            return

        self.updating_cron_schedule = True
        is_custom = self.custom_radio.isChecked()

        # Set the enabled state of the ComboBoxes based on the checked radio button
        cbox_states = {
            self.min_cbox: self.hourly_radio.isChecked() or self.daily_radio.isChecked() or self.weekly_radio.isChecked() or is_custom,
            self.hour_cbox: self.daily_radio.isChecked() or self.weekly_radio.isChecked() or is_custom,
            self.date_cbox: is_custom,
            self.month_cbox: is_custom,
            self.day_cbox: self.weekly_radio.isChecked() or is_custom,
        }

        for cbox, state in cbox_states.items():
            cbox.setEnabled(state)
            if not state:
                cbox.setCurrentIndex(0)

        minute = self.min_cbox.currentText() if self.min_cbox.currentText() != "Minute" else "*"
        hour = self.hour_cbox.currentText() if self.hour_cbox.currentText() != "Hour" else "*"
        date = self.date_cbox.currentText() if is_custom and self.date_cbox.currentText() != "Date" else "*"
        month = str(self.month_cbox.currentIndex()) if is_custom and self.month_cbox.currentText() != "Month" else "*"
        day = str(self.day_cbox.currentIndex() - 1) if (is_custom or self.weekly_radio.isChecked()) and self.day_cbox.currentText() != "Day" else "*"

        if self.hourly_radio.isChecked():
            minute = "0" if minute == "*" else minute
            self.cron_schedule.setPlainText(f"{minute} * * * *")
        elif self.daily_radio.isChecked():
            minute = "0" if minute == "*" else minute
            hour = "0" if hour == "*" else hour
            self.cron_schedule.setPlainText(f"{minute} {hour} * * *")
        elif self.weekly_radio.isChecked():
            minute = "0" if minute == "*" else minute
            hour = "0" if hour == "*" else hour
            day = "0" if day == "*" else day
            self.cron_schedule.setPlainText(f"{minute} {hour} * * {day}")
        else:
            cron_expression = f"{minute} {hour} {date} {month} {day}"
            self.cron_schedule.setPlainText(cron_expression)

        self.updating_cron_schedule = False


class NextGeNmapGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        loadUi('nextgenmap.ui', self)
        self.actionExit.triggered.connect(lambda: QApplication.quit())
        self.profile_model = SeparatorStandardItemModel(self)
        self.script_model = SeparatorStandardItemModel(self)
        self.scheduler_dialog = SchedulerDialog(parent=self, main_window=self)
        self.vuln_dialog = VulnResultsDialog(parent=self, main_window=self)
        self.nmap_results = None
        self.init_ui()

    def init_ui(self):
        self.setup_profiles()
        self.scan_button.clicked.connect(self.start_scan)
        self.cancel_button.clicked.connect(self.terminate_scan)
        self.target_entry.textChanged.connect(lambda: (self.update_command(), self.update_target()))
        self.command_entry.textChanged.connect(self.update_target_from_command)
        self.profile_combobox.currentIndexChanged.connect(self.update_command)
        self.verbose_checkbox.stateChanged.connect(self.update_command)
        self.port_range_entry.textChanged.connect(self.update_command)
        self.vuln_scripts_combobox.currentIndexChanged.connect(self.update_command)
        self.script_args_entry.textChanged.connect(self.update_command)
        self.schedule_button.clicked.connect(self.show_scheduler)
        self.nmap_progress.setVisible(False)
        self.statusbar.showMessage("Status: Idle")
        self.update_command()
        ###
        self.target_entry.setText("scanme.nmap.org")


    def setup_profiles(self):
        profile_categories = {
            "Zenmap default profiles": [
                "Intense scan", "Intense scan plus UDP", "Intense scan, all TCP ports", "Intense scan, no ping",
                "Ping scan", "Quick scan", "Intense Comprehensive Scan", "Quick scan plus", "Quick traceroute",
                "Regular scan", "Slow comprehensive scan"
            ],
            "nextgeNmap profiles": [
                "EternalBlue scan", "Heartbleed scan", "Common web vulnerabilities scan", "Drupal vulnerability scan",
                "WordPress vulnerability scan", "Joomla vulnerability scan", "SMB vulnerabilities scan",
                "SSL/TLS vulnerabilities scan", "DNS zone transfer scan", "SNMP vulnerabilities scan",
                "NTP DDoS amplification scan", "Mail servers vulnerabilities scan", "Brute force FTP login",
                "Brute force SSH login", "Brute force Telnet login", "Brute force RDP login", "Brute force HTTP login",
                "ALL scripts matching \"vuln\" category"
            ]
        }

        self.profile_details = {
            ## Zenmap default profiles ##
            "Intense scan": {"nmap_args": "-T4 -A -v"},
            "Intense scan plus UDP": {"nmap_args": "-sS -sU -T4 -A -v"},
            "Intense scan, all TCP ports": {"nmap_args": "-p 1-65535 -T4 -A -v"},
            "Intense scan, no ping": {"nmap_args": "-T4 -A -v -Pn"},
            "Intense Scan, no Ping, Agressive": {"nmap_args": "-T4 -A -v -Pn --script 'default or (discovery and safe)'"},
            "Intense Comprehensive Scan": {"nmap_args": "-p 1-65535 -T4 -A -v -PE -PP -PS80,443,21,22,25,3389 -PA3389 -PU40125 -PY -g 53 --script 'default or (discovery and safe)'"},
            "Ping scan": {"nmap_args": "-sn"},
            "Quick scan": {"nmap_args": "-T4 -F"},
            "Quick scan plus": {"nmap_args": "-sV -T4 -O -F --version-light"},
            "Quick traceroute": {"nmap_args": "-sn --traceroute"},
            "Regular scan": {"nmap_args": ""},
            "Slow comprehensive scan": {"nmap_args": "-sS -sU -T4 -A -v -PE -PP -PS80,443 -PA3389 -PU40125 -PY -g 53 --script \"default or (discovery and safe)\""},
            "UDP SYN Scan": {"nmap_args": "-sU -sS -T4 -A -v --top-ports 200"},
            "TCP SYN Scan": {"nmap_args": "-sS -T4 -A -v --top-ports 200"},
            ## nextgeNmap profiles ##
            "EternalBlue scan": {"nmap_args": "-p 445 --script smb-vuln-ms17-010"},
            "Heartbleed scan": {"nmap_args": "-p 443 --script ssl-heartbleed"},
            "Common web vulnerabilities scan": {"nmap_args": "-p 80,443 --script http-enum,http-vuln-cve2010-2861,http-vuln-cve2017-8917,http-vuln-cve2011-3192,http-vuln-cve2011-3368,http-vuln-cve2012-1823,http-vuln-cve2013-7091,http-vuln-cve2014-3704,http-vuln-cve2014-8877,http-vuln-cve2015-1427,http-vuln-cve2015-1635"},
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
            "ALL scripts matching \"vuln\" category": {"nmap_args": "-p 1-65535 --script vuln"},
            }

        script_categories = {
            "scip AG Scripts": [
                "vulscan", "httprecon"
            ],
            "vulnersCom Scripts": [
                "vulners", "http-vulners-regex"
            ],
            "nccgroup Scripts": [
                "21nails", "pjl-info-config", "http-lexmark-version"
            ]
        }

        self.script_details = {
            "":
                {"nmap_args": "", "script_args": ""},
            "vulscan":
                {"nmap_args": " --script ./nse/scipag/vulscan", "script_args": "vulscanoutput=detailed"},
            "httprecon":
                {"nmap_args": " --script ./nse/scipag/httprecon", "script_args": "httprecontoplist=20"},
            "vulners": 
                {"nmap_args": " --script ./nse/vulners", "script_args": "mincvss=7.5"},
            "http-vulners-regex":
                {"nmap_args": " --script ./nse/http-vulners-regex", "script_args": 'paths={\"/\", \"/api/v1/\"}'},
            "21nails":
                {"nmap_args": " --script ./nse/smtp-vuln-cve2020-28017-through-28026-21nails", "script_args": ""},
            "pjl-info-config":
                {"nmap_args": " --script ./nse/pjl-info-config", "script_args": ""},
            "http-lexmark-version":
                {"nmap_args": " --script ./nse/http-lexmark-version", "script_args": ""},
        }

        self.profile_combobox.setModel(self.profile_model)
        self.vuln_scripts_combobox.setModel(self.script_model)

        for category, profile_list in profile_categories.items():
            append_items(self.profile_model, [f"-- {category} --"], is_separator=True)
            append_items(self.profile_model, profile_list)

        append_items(self.script_model, [""])
        for category, script_list in script_categories.items():
            append_items(self.script_model, [f"-- {category} --"], is_separator=True)
            append_items(self.script_model, script_list)


    def show_scheduler(self):
        self.scheduler_dialog.cron_preview.setPlainText(self.command_entry.text())
        self.scheduler_dialog.exec()
        
    def show_vulns(self, vuln_list):
        self.vuln_dialog.vuln_tabs.setTabText(0, vuln_list[0])
        self.vuln_dialog.output_list.addItems(vuln_list[1].splitlines())
        self.vuln_dialog.exec()
        
    def schedule_scan(self):
        command_entry = self.scheduler_dialog.cron_preview.toPlainText()
        python_path = sys.executable
        script_path = os.path.abspath(__file__)
        output_file = os.path.join(os.path.dirname(__file__), self.scheduler_dialog.xml_output.toPlainText())
        command = f'{python_path} {script_path} --scan --command "{command_entry}" --output {output_file}'
        cron_time = self.scheduler_dialog.cron_schedule.toPlainText() 
        self.user_cron = CronTab(user=True)
        self.job = self.user_cron.new(command, comment='nextgeNmap scheduled scan')
        self.job.setall(cron_time)
        self.user_cron.write()


    def update_progress(self, text):
        # Parse the output to get progress and ETC
        progress_match = re.search(r'About ([\d.]+)% done', text)
        etc_match = re.search(r'ETC: (\d{2}:\d{2}) \((\d{1,2}:\d{2}:\d{2}) remaining\)', text)

        if progress_match:
            progress = floor(float(progress_match.group(1)))
            self.nmap_progress.setValue(progress)
            self.nmap_progress.setVisible(True) if not self.nmap_progress.isVisible() else None

        if etc_match:
            etc_time = etc_match.group(1)
            remaining_time = etc_match.group(2)
            self.statusbar.showMessage(f"Estimated time: {etc_time} (about {remaining_time} remaining)")

    def apply_highlight_rules(self, text):
        cursor = self.nmap_output_text.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)

        cursor.insertText(text)

        highlight_rules = { # thank you Zenmap for the regexes ~
            "date": {
                "bold": True,
                "italic": False,
                "underline": False,
                "text": [0, 0, 0],
                "highlight": [65535, 65535, 65535],
                "regex": r"\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}\s.{1,4}" },
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

        for rule_name in highlight_rules:
            rule = highlight_rules[rule_name]
            regex = rule["regex"]
            pattern = re.compile(regex, re.MULTILINE)

            for match in pattern.finditer(self.nmap_output_text.toPlainText()):
                start = match.start()
                end = match.end()

                cursor.setPosition(start)
                cursor.setPosition(end, QTextCursor.MoveMode.KeepAnchor)

                format = QTextCharFormat()
                format.setFontWeight(QFont.Weight.Bold if rule["bold"] else QFont.Weight.Normal)
                #format.setFontItalic(rule["italic"])
                format.setFontUnderline(rule["underline"])
                format.setForeground(QColor(rule["text"][0]//257, rule["text"][1]//257, rule["text"][2]//257))
                #format.setBackground(QColor(rule["highlight"][0]//257, rule["highlight"][1]//257, rule["highlight"][2]//257))
                cursor.setCharFormat(format)
                cursor.clearSelection()

    def handle_stdout(self, data, sender=None):
        self.apply_highlight_rules(data)
        self.update_progress(data.strip())

    def handle_stderr(self, data, sender=None):
        self.apply_highlight_rules(data)
        # self.nmap_output_text.append(data.strip())
        # self.nmap_output_text.moveCursor(QTextCursor.MoveOperation.End)

    def terminate_scan(self):
        if self.nmap_process:
            self.nmap_process.terminate()
            self.nmap_process = None
        self.scan_button.setEnabled(True)
        self.cancel_button.setEnabled(False)
        self.nmap_progress.setVisible(False)
        self.statusbar.showMessage("Status: Idle")
            
    def scan_error(self, error_message):
        self.nmap_output_text.append("Scan aborted!") # {}".format(error_message))
        self.terminate_scan()

    def scan_finished(self, output_file, output_xml, sender=None):
        self.nmap_results = PortScanner()
        with open(output_xml, 'r') as xml_file:
            try:
                self.nmap_results.analyse_nmap_xml_scan(xml_file.read())
                self.populate_ports_hosts_grid()
            except PortScannerError as e:
                self.scan_error(str(e))
        os.remove(output_xml)
        self.terminate_scan()

    def start_scan(self):
        self.nmap_process = NmapProcess(self.command_entry.text().strip(), output_file=None, stdout_callback=self.handle_stdout, stderr_callback=self.handle_stderr, finished_callback=self.scan_finished)
        self.nmap_process.run()
        self.scan_button.setEnabled(False)
        self.cancel_button.setEnabled(True)
        self.statusbar.showMessage("Status: Running scan...")

    def update_target(self):
        target = self.target_entry.text()
        command = self.command_entry.text()
        command_parts = command.split()
        if command_parts and command_parts[-1] == "{target}":
            command_parts[-1] = target
            self.command_entry.setText(" ".join(command_parts))

    def update_target_from_command(self):
        target = self.target_entry.text()
        command = self.command_entry.text()

        # Split the command text into words and get the last word
        words = command.split()
        last_word = words[-1] if words else ""

        # Check if the last word matches the target text and is not empty
        if last_word == target and target != "":
            self.target_entry.setText(last_word)

    def remove_argument(self, arguments, arg_to_remove):
        new_arguments = []
        i = 0
        while i < len(arguments):
            arg = arguments[i]
            if arg != arg_to_remove:
                new_arguments.append(arg)
            else:
                # Check if the next word does not start with '-' and is not the last word in the command
                if i < len(arguments) - 2 and not arguments[i + 1].startswith('-'):
                    i += 1  # Skip the next word
            i += 1
        return new_arguments

    def update_command(self):
        target = self.target_entry.text()
        port_range = self.port_range_entry.text().replace(" ", ",")
        profile = self.profile_combobox.currentText()
        vuln_script = self.vuln_scripts_combobox.currentText()
        current_command = self.command_entry.text()

        if not current_command:
            self.command_entry.setText(f"nmap {target}")
            return

        command_list = ["nmap"] #shlex.split(current_command)[1:-1]

        if profile in self.profile_details:
            command_list += shlex.split(self.profile_details[profile].get('nmap_args', ''))

        if vuln_script in self.script_details:
            script_nmap_args = shlex.split(self.script_details[vuln_script].get('nmap_args', ''))
            script_args = shlex.split(self.script_details[vuln_script].get('script_args', ''))
            if self.script_args_entry.text() == "" and vuln_script != "":
                self.script_args_entry.setPlaceholderText(" ".join(script_args)) # + " (" + vuln_script + ".nse)")

            command_list += script_nmap_args + script_args

        if "-v" not in command_list and self.verbose_checkbox.isChecked():
            command_list += ["-v"]
        elif "-v" in command_list and self.verbose_checkbox.isChecked():
            self.verbose_checkbox.setChecked(True)
        elif "-v" in command_list and not self.verbose_checkbox.isChecked():
            command_list = self.remove_argument(command_list, "-v")

        if "-p" not in command_list and port_range:
            command_list += ["-p", f"{port_range}"]
        elif "-p" in command_list and port_range:
            command_list = self.remove_argument(command_list, "-p")
            command_list += ["-p", f"{port_range}"]

        #command_list = [arg for arg in command_list if arg != "{target}"]

        self.command_entry.setText(" ".join(command_list + [target]))

    def populate_ports_hosts_grid(self):
        self.ports_hosts_table.clearContents()
        self.ports_hosts_table.setRowCount(0)
        row_num = 0
        for host in self.nmap_results.all_hosts():
            if self.nmap_results[host].state() == "up":
                for proto in self.nmap_results[host].all_protocols():
                    lport = self.nmap_results[host][proto].keys()
                    for port in lport:
                        status = self.nmap_results[host][proto][port]["state"]
                        service = self.nmap_results[host][proto][port]["name"]
                        version = self.nmap_results[host][proto][port]["product"] + " " + self.nmap_results[host][proto][port]["version"]

                        script_list = []
                        script_result_button = QPushButton(f"No Script Results")
                        script_result_button.setEnabled(False)

                        script_output = self.nmap_results[host][proto][port].get('script', {})
                        if script_output:
                            print(f"script_output: {script_output}")
                            for script_name, output in script_output.items():
                                print(f"Script: {script_name}")
                                print(f"Output:\n{output}")
                                if output:
                                    script_list += [script_name, output]
                                    script_result_button = QPushButton(f"Show Results: {script_name}")
                                    script_result_button.setEnabled(True)
                                    script_result_button.clicked.connect(lambda _, vl=script_list: self.show_vulns(vl))
                        self.ports_hosts_table.insertRow(row_num)
                        self.ports_hosts_table.setItem(row_num, 0, QTableWidgetItem("✓"))
                        self.ports_hosts_table.setItem(row_num, 1, QTableWidgetItem(str(port)))
                        self.ports_hosts_table.setItem(row_num, 2, QTableWidgetItem(proto))
                        self.ports_hosts_table.setItem(row_num, 3, QTableWidgetItem(status))
                        self.ports_hosts_table.setItem(row_num, 4, QTableWidgetItem(service))
                        self.ports_hosts_table.setCellWidget(row_num, 5, script_result_button)
                        self.ports_hosts_table.setItem(row_num, 6, QTableWidgetItem(version))
                        self.ports_hosts_table.resizeColumnsToContents()
                        row_num += 1

def append_items(model, items, is_separator=False):
    for text in items:
        item = QStandardItem(text)
        if is_separator:
            item.setData("separator", Qt.ItemDataRole.UserRole)
            font = item.font()
            #font.setBold(True)
            item.setFont(font)
        model.appendRow(item)

def cron_finished(output_file, output_xml, sender=None):
    with open(output_xml, 'r') as temp_xml: input_xml = temp_xml.read()
    input_xml = re.sub(r'<\?xml.*?\?>', '', input_xml, count=1)
    input_xml = re.sub(r'<nmaprun.*?>', '', input_xml, count=1)
    input_xml = re.sub(r'</nmaprun>', '', input_xml, count=1)
    with open(output_file, 'a') as final_report: final_report.write(input_xml)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='NextGeNmap')
    parser.add_argument('--scan', action='store_true', help='Run scan in the background')
    parser.add_argument('--command', type=str, help='Full command with target and arguments')
    parser.add_argument('--output', type=str, help='Output file')
    args = parser.parse_args()

    if args.scan:
        try:
            cron_scan = NmapProcess(args.command, args.output, finished_callback=cron_finished, from_cli=True)
            cron_scan.run()
        except Exception as e:
            print(f"Failed to start scan: {e}")
    else:
        app = QApplication(sys.argv)
        app.setStyle(QStyleFactory.create('Fusion'))
        window = NextGeNmapGUI()
        window.show()
        sys.exit(app.exec())
