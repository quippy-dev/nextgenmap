import sys, os, re, argparse
from math import floor
from nmap import PortScanner
from lxml import etree
from PyQt6.QtCore import (Qt, QFile, QTextStream, QIODevice, QTimer)
from PyQt6.QtGui import (QIcon, QTextCursor, QStandardItemModel, QStandardItem,
                         QColor, QTextCharFormat, QTextDocument, QFont)
from PyQt6.QtWidgets import (QApplication, QMainWindow, QStyleFactory, QTableWidgetItem,
                             QDialog, QPushButton, QWidget, QVBoxLayout,
                             QTableWidget, QHBoxLayout, QAbstractItemView, QListWidget,
                             QSplitter, QTextBrowser, QListWidgetItem)
from res.main_resources import *
from res.main_window import Ui_MainWindow
from res.vuln_dialog import Ui_VulnsDialog
from res.scheduler import SchedulerDialog
from res.searchsploit import (SearchSploitWidget)
from res.nmap_utils import (NmapProcess, setup_profiles, highlight_rules,
                            custom_split, remove_argument, exclude_args_dict)


script_name = os.path.basename(sys.modules['__main__'].__file__)
script_dir = os.path.abspath(os.path.dirname(sys.modules['__main__'].__file__))

print(f"Script name: {script_name}")
print(f"Script directory: {script_dir}")


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


def linkify(text):
    url_pattern = re.compile(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+')
    lines = text.splitlines()
    processed_lines = [url_pattern.sub(r'<a href="\g<0>">\g<0></a>', line) for line in lines]
    return '<br>'.join(processed_lines)


def cron_finished(output_filename, output_xml, generate_html, sender=None):
    if not output_filename:
        output_filename = "NextgeNmap-cronjob"

    name, extension = os.path.splitext(output_filename)
    print(f"cron_finished: {name}, {extension}")

    # Read our temporary XML file into memory
    with open(output_xml, 'r') as f: xml_data = f.read()
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


def append_items(model, items, is_separator=False):
    for text in items:
        item = QStandardItem(text)
        if is_separator:
            item.setData("separator", Qt.ItemDataRole.UserRole)
            font = item.font()
            font.setBold(True)
            item.setForeground(QColor(0, 123, 255))
            item.setFont(font)
        model.appendRow(item)


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


class NextgeNmapGUI(QMainWindow, Ui_MainWindow):
    def __init__(self):
        super().__init__()
        app_icon = QIcon(":/res/icon.svg")
        self.setWindowIcon(app_icon)
        self.setupUi(self)
        self.actionExit.triggered.connect(lambda: QApplication.quit())
        self.profile_model = SeparatorStandardItemModel(self)
        self.script_model = SeparatorStandardItemModel(self)
        self.scheduler_dialog = SchedulerDialog(parent=self, main_window=self)
        self.vuln_dialog = VulnResultsDialog(parent=self, main_window=self)
        self.searchsploit = SearchSploitWidget(parent=self)
        self.nmap_results = None
        self.host_ports_tables = {}
        self.buffered_output = ""
        self.update_output_text()
        self.init_ui()

        # Load Markdown content from the resource file
        load_content_into_text_browser(self.overview_text_browser, ":/doc/overview.md")
        load_content_into_text_browser(self.profiles_text_browser, ":/doc/customprofiles.md")
        load_content_into_text_browser(self.options_text_browser, ":/doc/nmapoptions.md")
        load_content_into_text_browser(self.glossary_text_browser, ":/doc/glossary.md")
        # Load HTML content from the resource file
        load_content_into_text_browser(self.about_text_browser, ":/about.html", True)

        self.tab_widget.insertTab(2, self.searchsploit, "SearchSploit")

    def init_ui(self):
        setup_profiles(self)
        self.profile_combobox.setCurrentIndex(2)
        self.scan_button.clicked.connect(self.start_scan)
        self.cancel_button.clicked.connect(self.terminate_scan)
        self.target_entry.textChanged.connect(lambda: (self.update_command(), self.target_entry.setPlaceholderText("")))
        self.port_range_entry.textChanged.connect(lambda: (self.update_command()))  # , self.port_range_entry.setPlaceholderText("")))
        self.vuln_scripts_combobox.currentIndexChanged.connect(lambda: (self.update_command(), self.script_args_entry.setText("")))
        self.command_entry.textChanged.connect(lambda: (self.update_target_from_command(), self.update_command()))
        self.script_args_entry.textChanged.connect(self.update_command)
        self.profile_combobox.currentIndexChanged.connect(self.update_command)
        self.verbose_checkbox.stateChanged.connect(self.update_command)
        self.verbose_spinbox.valueChanged.connect(self.update_command)
        self.schedule_button.clicked.connect(self.show_scheduler)
        self.hosts_list.currentRowChanged.connect(self.on_host_selected)
        self.nmap_progress.setVisible(False)
        self.statusbar.showMessage("Status: Idle")
        self.statusbar.setStyleSheet("QStatusBar{padding-left:8px;color:gray;}")
        self.nmap_output_text.verticalScrollBar().setValue(self.nmap_output_text.verticalScrollBar().maximum())

        self.profile_model = SeparatorStandardItemModel(self)
        self.script_model = SeparatorStandardItemModel(self)
        self.profile_combobox.setModel(self.profile_model)
        self.vuln_scripts_combobox.setModel(self.script_model)
        append_items(self.profile_model, {"": {"": {"": ""}}})
        append_items(self.script_model, {"": {"": {"": ""}}})

        for category, profile_or_script_dict in self.profile_and_script_details.items():
            if "Zenmap" in category or "NextGeNmap" in category:
                append_items(self.profile_model, [f"-- {category} --"], is_separator=True)
                append_items(self.profile_model, list(profile_or_script_dict.keys()))
            else:
                append_items(self.script_model, [f"-- {category} --"], is_separator=True)
                append_items(self.script_model, list(profile_or_script_dict.keys()))

        self.update_command()
        self.target_entry.setFocus()

    def show_scheduler(self):
        self.scheduler_dialog.schedule_scan()
        self.scheduler_dialog.exec()

    def show_vulns(self, vuln_list):
        self.vuln_dialog.vuln_tabs.clear()  # Clear existing tabs
        new_tab = QWidget()
        new_output_list = QListWidget()
        new_output_list.setMaximumWidth(300)  # Set the maximum width of the list

        for i in range(0, len(vuln_list), 2):
            script_name = vuln_list[i]
            item = QListWidgetItem(script_name)
            new_output_list.addItem(item)

        max_item_width = new_output_list.sizeHintForColumn(0)
        details_view = QTextBrowser()
        details_view.setHtml("Click on a script to view details")
        details_view.setOpenExternalLinks(True)
        splitter = QSplitter()
        splitter.addWidget(new_output_list)
        splitter.addWidget(details_view)
        splitter.setStretchFactor(0, 0)
        splitter.setStretchFactor(1, 1)
        splitter.setSizes([max_item_width, 100])

        # Set up layout for the new tab
        layout = QVBoxLayout()
        layout.addWidget(splitter)
        new_tab.setLayout(layout)

        new_output_list.currentRowChanged.connect(lambda index: details_view.setHtml(linkify(vuln_list[index * 2 + 1])))

        # Add the new tab to the vuln_tabs
        self.vuln_dialog.vuln_tabs.addTab(new_tab, self.profile_combobox.currentText() + " - " + self.target_entry.text())
        self.vuln_dialog.exec()

    def update_output_text(self):
        if self.buffered_output:
            self.apply_highlight_rules(self.buffered_output)
            self.update_progress(self.buffered_output)
            self.buffered_output = ""
        QTimer.singleShot(500, self.update_output_text)

    def apply_highlight_rules(self, text):
        cursor = self.nmap_output_text.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        cursor.insertText(text)

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
                # format.setFontItalic(rule["italic"])
                format.setFontUnderline(rule["underline"])
                format.setForeground(QColor(rule["text"][0] // 257, rule["text"][1] // 257, rule["text"][2] // 257))
                # format.setBackground(QColor(rule["highlight"][0]//257, rule["highlight"][1]//257, rule["highlight"][2]//257))
                cursor.setCharFormat(format)
                cursor.clearSelection()

        # Move the cursor to the end of the text
        cursor.movePosition(QTextCursor.MoveOperation.End)
        # Update the QTextEdit's cursor
        self.nmap_output_text.setTextCursor(cursor)
        # Scroll the view to make the cursor visible
        self.nmap_output_text.ensureCursorVisible()

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

    def handle_stdout(self, data, sender=None):
        self.buffered_output += data

    def handle_stderr(self, data, sender=None):
        self.buffered_output += data

    def terminate_scan(self):
        if self.nmap_process:
            self.nmap_process.kill()
        self.scan_button.setEnabled(True)
        self.cancel_button.setEnabled(False)
        self.nmap_progress.setVisible(False)
        self.statusbar.showMessage("Status: Idle")

    def scan_error(self, error_message):
        self.nmap_output_text.append("Scan aborted! {}".format(error_message))
        self.terminate_scan()

    def scan_finished(self, output_filename, output_xml, generate_html, sender=None):
        self.nmap_results = PortScanner()
        with open(output_xml, 'r') as xml_blob:
            xml_root = None
            xml_data = xml_blob.read()
            try:
                self.nmap_results.analyse_nmap_xml_scan(xml_data)
                self.populate_ports_hosts_grid()
                xml_root = etree.fromstring(xml_data.encode())

                services_to_search = self.searchsploit.get_services_to_search(xml_root)
                for services in services_to_search.values():
                    self.buffered_output += (f"Running SearchSploit on services: {services}...\n")
                self.searchsploit.run_searchsploit_on_services(services_to_search)
                self.buffered_output += "Finished running SearchSploit\n"
            except Exception as e:
                print(str(e))
                # self.scan_error(str(e))
        os.remove(output_xml)
        self.terminate_scan()

    def start_scan(self):
        # Use a QTimer to start the scan in the event loop
        QTimer.singleShot(0, self._start_scan)

    def _start_scan(self):
        command = self.command_entry.text().strip()
        self.final_command_text.setText(command)
        self.nmap_process = NmapProcess(command, output_filename=None, stdout_callback=self.handle_stdout, stderr_callback=self.handle_stderr, finished_callback=self.scan_finished)
        self.nmap_process.run()

        # Set the active tab to the output tab:
        self.tab_widget.setCurrentIndex(0)

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
        current_command = self.command_entry.text()
        # command_parts = current_command.split(" ")
        command_parts = [t for t in current_command.strip().split(" ") if t]
        new_target = self.parse_target_hosts(command_parts)

        if new_target != self.target_entry.text():
            self.target_entry.blockSignals(True)
            self.target_entry.setText(new_target + " ")
            self.target_entry.blockSignals(False)

    def parse_target_hosts(self, command_parts):
        # nmap_utils.exclude_args_dict
        target_hosts = []
        skip_next = False

        for i, part in enumerate(command_parts):
            if skip_next:
                skip_next = False
                continue
            # need to make sure part does not contain and/or/not:
            if part.startswith('-') or part in ['and', 'or', 'not']:
                found = False
                for args in exclude_args_dict:
                    if part in args:
                        found = True
                        skip_next = True
                        break
                if found:
                    continue
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
        if self.sender(): sender = self.sender().objectName()
        else: sender = None

        targets = [t for t in self.target_entry.text().strip().split(" ") if t]
        port_range = self.port_range_entry.text().replace(" ", ",")
        profile = self.profile_combobox.currentText()
        vuln_script = self.vuln_scripts_combobox.currentText()
        script_args_entry = self.script_args_entry.text()
        script_args_value = None
        command_list = []

        # Check for Zenmap default profiles
        if profile in self.profile_and_script_details.get("Zenmap default profiles", {}).keys():
            command_list += custom_split(self.profile_and_script_details["Zenmap default profiles"][profile].get('nmap_args', ''))
            self.vuln_scripts_combobox.setEnabled("--script" not in command_list)
            self.vuln_scripts_combobox.setCurrentIndex(0 if "--script" in command_list else self.vuln_scripts_combobox.currentIndex())

        # Check for NextGeNmap developer profiles
        if profile in self.profile_and_script_details.get("NextGeNmap developer profiles", {}).keys():
            command_list += custom_split(self.profile_and_script_details["NextGeNmap developer profiles"][profile].get('nmap_args', ''))
            self.vuln_scripts_combobox.setEnabled("--script" not in command_list)
            self.vuln_scripts_combobox.setCurrentIndex(0 if "--script" in command_list else self.vuln_scripts_combobox.currentIndex())

        # Check for script categories
        for script_category in ["scip AG Scripts", "vulnersCom Scripts", "nccgroup Scripts", "NextgeNmap curated scripts"]:
            if vuln_script in self.profile_and_script_details.get(script_category, {}).keys():
                script_nmap_args = custom_split(self.profile_and_script_details[script_category][vuln_script].get('nmap_args', ''))
                script_args_value = script_args_entry if script_args_entry else " ".join(custom_split(self.profile_and_script_details[script_category][vuln_script].get('script_args', '')))
                command_list += script_nmap_args

            if "--script-args" not in command_list and script_args_value:
                command_list += ["--script-args", script_args_value]
            elif "--script-args" in command_list and script_args_value:
                command_list = remove_argument(command_list, "--script-args")
                command_list += ["--script-args", script_args_value]
            elif "--script-args" in command_list and not script_args_value:
                command_list = remove_argument(command_list, "--script-args")

        # Check if there's any -v through -vvvvv in command_list
        has_v_option = any([arg.startswith("-v") and set(arg) == {"-", "v"} for arg in command_list])
        self.verbose_checkbox.setEnabled(not has_v_option)
        self.verbose_spinbox.setEnabled(not has_v_option)
        if not has_v_option and self.verbose_checkbox.isChecked():
            verbosity = self.verbose_spinbox.value()
            command_list += ["-" + "v" * verbosity]

        self.port_range_entry.setEnabled("-F" not in command_list)
        if "-F" in command_list:
            self.port_range_entry.setPlaceholderText("Can't use with -F")
            self.port_range_entry.setText("")
            command_list = remove_argument(command_list, "-p")
        elif self.port_range_entry.placeholderText() == "Can't use with -F":
            self.port_range_entry.setPlaceholderText("")

        if port_range:
            self.port_range_entry.setPlaceholderText("")
            if "-p" not in command_list:
                command_list += ["-p", f"{port_range}"]
            else:
                command_list = remove_argument(command_list, "-p")
                command_list += ["-p", f"{port_range}"]

        proposed_args = ["nmap"] + command_list + targets
        if sender != "command_entry": self.command_entry.setText(" ".join(proposed_args))
        else:
            current_args = custom_split(self.command_entry.text())
            if current_args != proposed_args:
                self.profile_combobox.blockSignals(True)
                self.profile_combobox.setCurrentIndex(0)
                self.profile_combobox.blockSignals(False)
        self.script_args_entry.setText(self.extract_script_args(command_list))

    def create_host_page(self):
        new_host_widget = QWidget()
        new_host_layout = QVBoxLayout()
        new_ports_table = QTableWidget()
        new_horizontal_layout = QHBoxLayout()

        new_ports_table.setAlternatingRowColors(True)
        new_ports_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        new_ports_table.setColumnCount(8)
        new_ports_table.setHorizontalHeaderLabels(["Status", "Port", "Protocol", "State", "Service", "Script Output", "Version", "CPE"])

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
                        cpe = host_data[proto][port]["cpe"]
                        script_output = host_data[proto][port].get('script', {})

                        port_data = {
                            "port": port,
                            "protocol": proto,
                            "status": status,
                            "service": service,
                            "version": version,
                            "cpe": cpe,
                            "script_output": script_output
                        }
                        if status != "closed":
                            ports_list.append(port_data)

                    unique_ports = list({(p['port'], p['protocol']): p for p in ports_list}.values())
                    sorted_ports = sorted(unique_ports, key=lambda x: (x['port'], x['protocol']))

                    for unique_data in sorted_ports:
                        ports_table.insertRow(port_row_num)
                        ports_table.setItem(port_row_num, 0, QTableWidgetItem("✓"))
                        ports_table.setItem(port_row_num, 1, QTableWidgetItem(str(unique_data["port"])))
                        ports_table.setItem(port_row_num, 2, QTableWidgetItem(unique_data["protocol"]))
                        ports_table.setItem(port_row_num, 3, QTableWidgetItem(unique_data["status"]))
                        ports_table.setItem(port_row_num, 4, QTableWidgetItem(unique_data["service"]))

                        script_result_button = QPushButton("No Script Results")
                        script_result_button.setEnabled(False)
                        script_output = unique_data["script_output"]
                        script_list = []
                        if script_output:
                            for script_name, output in script_output.items():
                                if output:
                                    script_list += [script_name, output]
                                    script_result_button = QPushButton(f"Show Results: {script_name}") if len(script_list) <= 2 else QPushButton("Show Results")
                                    script_result_button.setEnabled(True)
                                    script_result_button.clicked.connect(lambda _, vl=script_list: self.show_vulns(vl))

                        ports_table.setCellWidget(port_row_num, 5, script_result_button)
                        ports_table.setItem(port_row_num, 6, QTableWidgetItem(unique_data["version"]))
                        ports_table.setItem(port_row_num, 7, QTableWidgetItem(unique_data["cpe"]))
                        ports_table.resizeColumnsToContents()
                        port_row_num += 1


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
