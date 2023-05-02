from datetime import datetime
import sys, os, tempfile, shlex, re, argparse
from math import floor
from nmap import PortScanner, PortScannerError
from crontab import CronTab
from lxml import etree
from PyQt6.QtWidgets import QApplication, QMainWindow, QStyleFactory, QTableWidgetItem, QDialog, QPushButton, QTextBrowser, QWidget, QVBoxLayout, QTableWidget, QHBoxLayout, QAbstractItemView, QListWidget
from PyQt6.QtCore import Qt, QProcess, QFile, QTextStream, QIODevice
from PyQt6.QtGui import QTextCursor, QTextOption, QStandardItemModel, QStandardItem, QColor, QTextCharFormat, QFont, QTextDocument
from res import Ui_MainWindow, Ui_VulnsDialog, Ui_SchedulerDialog

script_dir = os.path.dirname(os.path.abspath(__file__))

def load_content_into_text_browser(text_browser, resource_path, is_html=False):
    file = QFile(resource_path)
    if not file.open(QIODevice.OpenModeFlag.ReadOnly | QIODevice.OpenModeFlag.Text):
        return

    stream = QTextStream(file)
    content = stream.readAll()
    file.close()

    if is_html:
        text_browser.setHtml(content)
    else:
        document = QTextDocument()
        document.setMarkdown(content)
        text_browser.setDocument(document)

    text_browser.setOpenExternalLinks(True)


class NmapProcess:
    def __init__(self, command_entry, output_filename, stdout_callback=None, stderr_callback=None,
                 finished_callback=None, generate_html=False, from_cli=False, parent=None):
        self.command_entry = command_entry
        self.output_filename = output_filename
        self.process = None
        self.stdout_callback = stdout_callback
        self.stderr_callback = stderr_callback
        self.finished_callback = finished_callback
        self.generate_html = generate_html
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
        if self.output_filename is not None:
            self.output_xml = self.output_filename
        else:
            with tempfile.NamedTemporaryFile(suffix=".xml", prefix="NgNmap_", delete=False) as temp_xml: self.output_xml = temp_xml.name

        args = shlex.split(self.command_entry)
        args = args[1:]  # Remove the first argument
        args = strip_output_flags(args)  # Remove -oX and -oA arguments
        args = ["--datadir", script_dir, "-oX", self.output_xml] + args  # Add the new arguments to the front of the list
        print (args)

        
        self.process = QProcess()
        if self.stdout_callback:
            self.process.readyReadStandardOutput.connect(self.handle_stdout)
        if self.stderr_callback:
            self.process.readyReadStandardError.connect(self.handle_stderr)
        if self.finished_callback:
            self.process.finished.connect(lambda: self.finished_callback(self.output_filename, self.output_xml, self.generate_html, sender=self.process))

        self.process.start("nmap", args)

        if self.from_cli:
            self.process.waitForFinished(-1)


class SeparatorStandardItemModel(QStandardItemModel):
    def flags(self, index):
        if self.itemFromIndex(index).data(Qt.ItemDataRole.UserRole) == "separator":
            return Qt.ItemFlag.NoItemFlags
        return super().flags(index)


class VulnResultsDialog(QDialog, Ui_VulnsDialog):
    def __init__(self, parent=None, main_window=None):
        super().__init__(parent)
        self.setupUi(self)
        self.main_window = main_window
        self.init_ui()

    def init_ui(self):
        return


class SchedulerDialog(QDialog, Ui_SchedulerDialog):
    def __init__(self, parent=None, main_window=None):
        super().__init__(parent)
        self.setupUi(self)
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
        guru_format = f"https://crontab.guru/#{self.cron_schedule.toPlainText().replace(' ', '_')}"
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


class NextgeNmapGUI(QMainWindow, Ui_MainWindow):
    def __init__(self):
        super().__init__()
        self.setupUi(self)
        self.actionExit.triggered.connect(lambda: QApplication.quit())
        self.profile_model = SeparatorStandardItemModel(self)
        self.script_model = SeparatorStandardItemModel(self)
        self.scheduler_dialog = SchedulerDialog(parent=self, main_window=self)
        self.vuln_dialog = VulnResultsDialog(parent=self, main_window=self)
        self.nmap_results = None
        self.host_ports_tables = {}
        self.init_ui()

        # Load Markdown content from the resource file
        load_content_into_text_browser(self.overview_text_browser, ":/doc/overview.md")
        load_content_into_text_browser(self.profiles_text_browser, ":/doc/customprofiles.md")
        load_content_into_text_browser(self.options_text_browser, ":/doc/nmapoptions.md")
        load_content_into_text_browser(self.glossary_text_browser, ":/doc/glossary.md")

        # Load HTML content from the resource file
        load_content_into_text_browser(self.about_text_browser, ":/about.html", True)


    def init_ui(self):
        self.setup_profiles()
        self.scan_button.clicked.connect(self.start_scan)
        self.cancel_button.clicked.connect(self.terminate_scan)
        self.target_entry.textChanged.connect(lambda: (self.update_command(), self.target_entry.setPlaceholderText("")))
        self.port_range_entry.textChanged.connect(lambda: (self.update_command()))#, self.port_range_entry.setPlaceholderText("")))
        self.vuln_scripts_combobox.currentIndexChanged.connect(lambda: (self.update_command(), self.script_args_entry.setText("")))
        self.command_entry.textChanged.connect(self.update_target_from_command)
        self.script_args_entry.textChanged.connect(self.update_command)
        self.profile_combobox.currentIndexChanged.connect(self.update_command)
        self.verbose_checkbox.stateChanged.connect(self.update_command)
        self.verbose_spinbox.valueChanged.connect(self.update_command)
        self.schedule_button.clicked.connect(self.show_scheduler)
        self.hosts_list.currentRowChanged.connect(self.on_host_selected)
        self.nmap_progress.setVisible(False)
        self.statusbar.showMessage("Status: Idle")
        self.statusbar.setStyleSheet("QStatusBar{padding-left:8px;color:gray;}")
        self.update_command()

        self.target_entry.setText("devnas devnas-5 localhost 192.168.1.27")
        self.profile_combobox.setCurrentIndex(6)
        #self.command_entry.setText("nmap -sV -T5 --script vulscan/vulscan.nse scanme.nmap.org")

    def setup_profiles(self):
        profile_categories = {
            "Zenmap default profiles": [
                "Intense scan", "Intense scan plus UDP", "Intense scan, all TCP ports", "Intense scan, no ping",
                "Ping scan", "Quick scan", "Intense Comprehensive Scan", "Quick scan plus", "Quick traceroute",
                "Regular scan", "Slow comprehensive scan"
            ],
            "NextgeNmap profiles": [
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
            ## NextgeNmap profiles ##
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
            "ALL scripts matching \"vuln\" category": {"nmap_args": "-sV --script vuln"},
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
                {"nmap_args": " --script vulscan/vulscan.nse", "script_args": "vulscanoutput=listlink"},
            "httprecon":
                {"nmap_args": " --script httprecon/httprecon.nse", "script_args": "httprecontoplist=20"},
            "vulners": 
                {"nmap_args": " --script vulners", "script_args": "mincvss=7.5"},
            "http-vulners-regex":
                {"nmap_args": " --script http-vulners-regex", "script_args": 'paths=http-vulners-regex-paths.txt'},
            "21nails":
                {"nmap_args": " --script smtp-vuln-cve2020-28017-through-28026-21nails", "script_args": ""},
            "pjl-info-config":
                {"nmap_args": " --script pjl-info-config", "script_args": ""},
            "http-lexmark-version":
                {"nmap_args": " --script http-lexmark-version", "script_args": ""},
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
        self.vuln_dialog.vuln_tabs.clear()  # Clear existing tabs

        for i in range(0, len(vuln_list), 2):
            script_name = vuln_list[i]
            output = vuln_list[i + 1]

            # Create a new tab with a QListWidget for each script_name
            new_tab = QWidget()
            new_output_list = QListWidget()
            new_output_list.addItems(output.splitlines())

            # Set up layout for the new tab
            layout = QVBoxLayout()
            layout.addWidget(new_output_list)
            new_tab.setLayout(layout)

            # Add the new tab to the vuln_tabs
            self.vuln_dialog.vuln_tabs.addTab(new_tab, script_name)

        self.vuln_dialog.exec()
        
    def schedule_scan(self):
        command_entry = self.scheduler_dialog.cron_preview.toPlainText()
        python_path = sys.executable
        script_path = os.path.abspath(__file__)
        output_filename = os.path.join(os.path.dirname(__file__), self.scheduler_dialog.xml_output.toPlainText())
        command = f'{python_path} {script_path} --scan --html --command "{command_entry}" --output {output_filename}'
        cron_time = self.scheduler_dialog.cron_schedule.toPlainText() 
        self.user_cron = CronTab(user=True)
        self.job = self.user_cron.new(command, comment='NextgeNmap scheduled scan')
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
            self.statusbar.showMessage(f"ETC: {etc_time} (about {remaining_time} remaining)")

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

        self.nmap_output_text.verticalScrollBar().setValue(self.nmap_output_text.verticalScrollBar().maximum())

    def handle_stdout(self, data, sender=None):
        self.apply_highlight_rules(data)
        self.update_progress(data.strip())

    def handle_stderr(self, data, sender=None):
        self.apply_highlight_rules(data)

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

    def scan_finished(self, output_filename, output_xml, generate_html, sender=None):
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
        command = self.command_entry.text().strip()
        command = " ".join(strip_output_flags(shlex.split(command)))
        self.final_command_text.setText(command)
        self.nmap_process = NmapProcess(command, output_filename=None, stdout_callback=self.handle_stdout, stderr_callback=self.handle_stderr, finished_callback=self.scan_finished)
        self.nmap_process.run()
        
        # Clear the text before starting the scan
        self.nmap_output_text.clear()
        
        # Reset the text cursor position and formatting
        cursor = self.nmap_output_text.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.Start)
        cursor.setCharFormat(QTextCharFormat())
        self.nmap_output_text.setTextCursor(cursor)
        self.nmap_output_text.moveCursor(QTextCursor.MoveOperation.End)
        self.scan_button.setEnabled(False)
        self.cancel_button.setEnabled(True)
        self.statusbar.showMessage("Status: Running scan...")


    def update_target_from_command(self):
        #return
        current_command = self.command_entry.text()
        command_parts = current_command.split(" ")
        new_target = self.parse_target_hosts(command_parts)

        if new_target != self.target_entry.text():
            self.target_entry.blockSignals(True)
            self.target_entry.setText(new_target + " ")
            self.target_entry.blockSignals(False)

    def parse_target_hosts(self, command_parts):
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
            ("and",): None,
            ("or",): None,
            ("not",): None,
        }
        
        #command = shlex.split(command_parts)
        target_hosts = []
        skip_next = False

        for i, part in enumerate(command_parts):
            if skip_next:
                skip_next = False
                continue
            #need to make sure part does not contain and/or/not:
            if part.startswith('-') or part in ['and', 'or', 'not']:
                found = False
                for args in exclude_args_dict:
                    if part in args:
                        found = True
                        skip_next = True
                        break
                if found:
                    continue
            #elif i > 0 and command_parts[i - 1] in exclude_args_dict:
            elif i > 0:
                target_hosts.append(part)

        return ' '.join(target_hosts)


    def extract_script_args(self, command_parts):
        script_args_value = None
        if "--script-args" in command_parts:
            script_args_index = command_parts.index("--script-args")
            try:
                script_args_value = command_parts[script_args_index + 1]
            except IndexError:
                pass
        return script_args_value

    def update_command(self):
        targets = self.target_entry.text().strip().split(" ")
        port_range = self.port_range_entry.text().replace(" ", ",")
        profile = self.profile_combobox.currentText() if not self.profile_combobox.currentIndex() == 0 else "Intense scan"
        vuln_script = self.vuln_scripts_combobox.currentText()
        script_args_value = self.script_args_entry.text()

        command_list = []

        if profile in self.profile_details:
            command_list += shlex.split(self.profile_details[profile].get('nmap_args', ''))

        if vuln_script in self.script_details:
            script_nmap_args = shlex.split(self.script_details[vuln_script].get('nmap_args', ''))
            script_args_value = " ".join(shlex.split(self.script_details[vuln_script].get('script_args', ''))) if not script_args_value else script_args_value
            command_list += script_nmap_args

        # Check if there's any -v through -vvvvv in command_list
        has_v_option = any([arg.startswith("-v") and set(arg) == {"-","v"} for arg in command_list])
        self.verbose_checkbox.setEnabled(not has_v_option)
        self.verbose_spinbox.setEnabled(not has_v_option)
        if not has_v_option and self.verbose_checkbox.isChecked():
                verbosity = self.verbose_spinbox.value()
                command_list += ["-" + "v" * verbosity]
        # elif has_v_option and not self.verbose_checkbox.isChecked():
        #     self.verbose_checkbox.setChecked(True)

        self.port_range_entry.setEnabled(not "-F" in command_list)
        if "-F" in command_list:
            self.port_range_entry.setPlaceholderText("Can't use with -F")
            self.port_range_entry.setText("")
            command_list = remove_argument(command_list, "-p")
        else:
            self.port_range_entry.setPlaceholderText("")

        if port_range:
            if "-p" not in command_list:
                command_list += ["-p", f"{port_range}"]
            else:
                command_list = remove_argument(command_list, "-p")
                command_list += ["-p", f"{port_range}"]

        if "--script-args" not in command_list and script_args_value:
            command_list += ["--script-args", script_args_value]
        elif "--script-args" in command_list and script_args_value:
            command_list = remove_argument(command_list, "--script-args")
            command_list += ["--script-args", script_args_value]

        final_command = " ".join(["nmap"] + command_list + targets)
        #print(f'command_list: {final_command}')
        self.command_entry.setText(final_command)
        self.script_args_entry.setText(self.extract_script_args(command_list))

    def create_host_page(self):
        new_host_widget = QWidget()
        new_host_layout = QVBoxLayout()
        new_ports_table = QTableWidget()
        new_horizontal_layout = QHBoxLayout()

        new_ports_table.setAlternatingRowColors(True)
        new_ports_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        new_ports_table.setColumnCount(7)
        new_ports_table.setHorizontalHeaderLabels(["Status", "Port", "Protocol", "State", "Service", "Script Output", "Version"])

        new_horizontal_layout.addWidget(new_ports_table)  # Add the QTableWidget to the QHBoxLayout
        new_host_layout.addLayout(new_horizontal_layout)  # Add the QHBoxLayout to the QVBoxLayout
        new_host_widget.setLayout(new_host_layout)

        return new_host_widget, new_ports_table

    def on_host_selected(self, current_row):
        self.hosts_pages.setCurrentIndex(current_row)

    def populate_ports_hosts_grid(self):
        if not self.nmap_results:
            return

        host_row_num = 0

        for host in self.nmap_results.all_hosts():
            host_data = self.nmap_results[host]
            hostname = host_data['hostnames'][0]['name']

            if hostname:
                display_name = f"{hostname} ({host})"
            else:
                display_name = host
            #print(f"host: {host}\n host_ports_tables: {host_ports_tables}\n display_name: {display_name}\n host_row_num: {host_row_num}")
            if host not in self.host_ports_tables:
                host_widget, ports_table = self.create_host_page()
                widget_index = self.hosts_pages.addWidget(host_widget)
                self.hosts_list.insertItem(host_row_num, display_name)
                host_item = QTableWidgetItem(host)
                host_item.setToolTip(hostname)
                host_row_num += 1
                self.host_ports_tables[host] = {"widget_index": widget_index, "ports_table": ports_table}
            else:
                widget_index = self.host_ports_tables[host]["widget_index"]
                ports_table = self.host_ports_tables[host]["ports_table"]
                self.hosts_list.item(widget_index).setText(display_name)  # Update the existing host list item

            port_row_num = 0
            if host_data.state() == "up":
                ports_table.clearContents()
                ports_table.setRowCount(0)
                ports_list = []
                for proto in host_data.all_protocols():
                    lport = host_data[proto].keys()

                    for port in lport:
                        status = host_data[proto][port]["state"]
                        service = host_data[proto][port]["name"]
                        version = host_data[proto][port]["product"] + " " + host_data[proto][port]["version"]
                        script_output = host_data[proto][port].get('script', {})

                        port_data = {
                            "port": port,
                            "protocol": proto,
                            "status": status,
                            "service": service,
                            "version": version,
                            "script_output": script_output
                        }
                        ports_list.append(port_data)

                    unique_ports = list({(p['port'], p['protocol']): p for p in ports_list}.values())
                    sorted_ports = sorted(unique_ports, key=lambda x: (x['port'], x['protocol']))

                    for unique_data in sorted_ports:
                        #print(f"Port: {unique_data}")
                        ports_table.insertRow(port_row_num)
                        ports_table.setItem(port_row_num, 0, QTableWidgetItem("✓"))
                        ports_table.setItem(port_row_num, 1, QTableWidgetItem(str(unique_data["port"])))
                        ports_table.setItem(port_row_num, 2, QTableWidgetItem(unique_data["protocol"]))
                        ports_table.setItem(port_row_num, 3, QTableWidgetItem(unique_data["status"]))
                        ports_table.setItem(port_row_num, 4, QTableWidgetItem(unique_data["service"]))

                        script_result_button = QPushButton(f"No Script Results")
                        script_result_button.setEnabled(False)
                        script_output = unique_data["script_output"]
                        script_list = []
                        if script_output:
                            for script_name, output in script_output.items():
                                if output:
                                    script_list += [script_name, output]
                                    script_result_button = QPushButton(f"Show Results: {script_name}")
                                    script_result_button.setEnabled(True)
                                    script_result_button.clicked.connect(lambda _, vl=script_list: self.show_vulns(vl))

                        ports_table.setCellWidget(port_row_num, 5, script_result_button)
                        ports_table.setItem(port_row_num, 6, QTableWidgetItem(unique_data["version"]))
                        ports_table.resizeColumnsToContents()
                        port_row_num += 1

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

def append_items(model, items, is_separator=False):
    for text in items:
        item = QStandardItem(text)
        if is_separator:
            item.setData("separator", Qt.ItemDataRole.UserRole)
            font = item.font()
            font.setBold(True)
            item.setForeground(QColor(0, 123, 255))
            #item.setBackground(QColor(0, 0, 0))
            item.setFont(font)
        model.appendRow(item)

def cron_finished(output_filename, output_xml, generate_html, sender=None):
    if not output_filename:
        output_filename = "NextgeNmap-cronjob"

    name, extension = os.path.splitext(output_filename)
    print(f"cron_finished: {name}, {extension}")

    # Read our temporary XML file into memory
    with open(output_xml, 'r') as f: xml_data = f.read();
    os.remove(output_xml)

    if generate_html:
        if extension != '.html':
            output_filename = name + '.html'

        # Load the XSL stylesheet
        bootstrap_path = os.path.join(script_dir, 'res', 'nmap-bootstrap.xsl')
        with open(bootstrap_path, 'r') as f: xsl = f.read()

        # Parse the XML and XSL strings into etree objects
        xml_root = etree.fromstring(xml_data.encode())
        xsl_root = etree.fromstring(xsl.encode())

        # Create an XSLT transformer
        transformer = etree.XSLT(xsl_root)

        # Apply the transformation to the XML and save the HTML output
        html_root = transformer(xml_root)
        final_report = str(html_root)

    else:
        if extension != '.xml':
            output_filename = name + '.xml'
        final_report = xml_data

    with open(output_filename, 'w') as f: f.write(final_report)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='NextgeNmap')
    parser.add_argument('--scan', action='store_true', help='Run a scan with no GUI')
    parser.add_argument('--command', type=str, help='Full nmap command with target and arguments')
    parser.add_argument('--html', action='store_true', default=False, help='Output report in HTML format')
    parser.add_argument('--output-file', type=str, help='Output filename')
    args = parser.parse_args()

    if args.scan:
        try:
            cron_scan = NmapProcess(args.command, args.output_file, finished_callback=cron_finished, generate_html=args.html, from_cli=True)
            cron_scan.run()
        except Exception as e:
            print(f"Failed to start scan: {e}")
    else:
        app = QApplication(sys.argv)
        app.setStyle(QStyleFactory.create('Fusion'))
        window = NextgeNmapGUI()
        window.show()
        sys.exit(app.exec())
