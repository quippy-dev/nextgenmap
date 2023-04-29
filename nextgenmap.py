import sys
import os
import tempfile
import shlex
import re
from PyQt6.QtWidgets import QApplication, QMainWindow, QStyleFactory, QTableWidgetItem, QDialog, QPushButton
from PyQt6.QtCore import Qt, QProcess
from PyQt6.QtGui import QTextCursor, QTextOption
from PyQt6.uic import loadUi
from nmap import PortScanner, PortScannerError
from crontab import CronTab


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

    def init_ui(self):
        self.min_cbox.insertItem(0, "Minute")
        self.min_cbox.addItems([str(i) for i in range(0, 60)])
        self.hour_cbox.insertItem(0, "Hour")
        self.hour_cbox.addItems([str(i) for i in range(0, 24)])
        self.date_cbox.insertItem(0, "Date")
        self.date_cbox.addItems([str(i) for i in range(1, 32)])
        self.month_cbox.insertItem(0, "Month")
        self.month_cbox.addItems(["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Nov", "Dec"])
        self.day_cbox.insertItem(0, "Day")
        self.day_cbox.addItems(["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"])

        self.cron_schedule.document().setDefaultTextOption(QTextOption(Qt.AlignmentFlag.AlignCenter))
        self.hourly_radio.toggled.connect(self.update_cron_schedule)
        self.daily_radio.toggled.connect(self.update_cron_schedule)
        self.weekly_radio.toggled.connect(self.update_cron_schedule)
        self.custom_radio.toggled.connect(self.update_cron_schedule)
        self.min_cbox.currentIndexChanged.connect(self.update_cron_schedule)
        self.hour_cbox.currentIndexChanged.connect(self.update_cron_schedule)
        self.date_cbox.currentIndexChanged.connect(self.update_cron_schedule)
        self.month_cbox.currentIndexChanged.connect(self.update_cron_schedule)
        self.day_cbox.currentIndexChanged.connect(self.update_cron_schedule)
        self.cron_schedule.textChanged.connect(self.parse_cron_schedule)
        self.update_cron_schedule()

    def update_cbox_states(self, cron_text, cb_states, cb_indices):
        for i, part in enumerate(cron_text.split()):
            cb_states[i] = not any(c in part for c in ',/-')
            cb_indices[i] = int(part) + 1 if part.isdigit() else 0
            
    def parse_cron_schedule(self):
        # Provide a reference for the cron schedule
        guru_format = f"https://crontab.guru/#{self.cron_schedule.toPlainText().replace(' ', '_')}"
        self.guru_link.setText(f'<a href="{guru_format}"><span style="text-decoration:none;color:#007BFF;">{guru_format}</span></a>')
        
        if self.updating_cron_schedule:
            return

        cron_text = self.cron_schedule.toPlainText().strip()
        cron_pattern = re.compile(r'^(\*|\d+|\d+-\d+|\*/\d+|\d+(,\d+)*)( (\*|\d+|\d+-\d+|\*/\d+|\d+(,\d+)*)){4}$')
        if not cron_pattern.match(cron_text):
            return

        # Toggle custom radio button if not already checked
        if self.sender() and self.sender().hasFocus():
            self.toggling_custom_radio = True
            self.custom_radio.setChecked(True)
            for cb in [self.min_cbox, self.hour_cbox, self.date_cbox, self.month_cbox, self.day_cbox]:
                cb.setEnabled(True)
            self.toggling_custom_radio = False
            return

        cboxes = [self.min_cbox, self.hour_cbox, self.date_cbox, self.month_cbox, self.day_cbox]
        cb_states = [True] * 5
        cb_indices = [0] * 5

        self.update_cbox_states(cron_text, cb_states, cb_indices)

        for i, (cb, state, index) in enumerate(zip(cboxes, cb_states, cb_indices)):
            cb.setEnabled(state)
            cb.setCurrentIndex(index)

    def update_cron_schedule(self):
        # Return early if the sender is the QLineEdit cron_schedule or if toggling custom_radio due to parse_cron_schedule
        if self.sender() == self.cron_schedule or self.toggling_custom_radio:
            return
        self.updating_cron_schedule = True

        # Set the enabled state of the ComboBoxes based on the checked radio button
        is_custom = self.custom_radio.isChecked()
        self.min_cbox.setEnabled(True)
        self.hour_cbox.setEnabled(is_custom or self.daily_radio.isChecked() or self.weekly_radio.isChecked())
        self.date_cbox.setEnabled(is_custom)
        self.month_cbox.setEnabled(is_custom)
        self.day_cbox.setEnabled(is_custom or self.weekly_radio.isChecked())
        
        # Set current index to 0 for disabled QComboBox widgets
        for cb in [self.min_cbox, self.hour_cbox, self.date_cbox, self.month_cbox, self.day_cbox]:
            if not cb.isEnabled():
                cb.setCurrentIndex(0)
        
        # Update the cron expression
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
            hour = "12" if hour == "*" else hour
            self.cron_schedule.setPlainText(f"{minute} {hour} * * *")
        elif self.weekly_radio.isChecked():
            minute = "0" if minute == "*" else minute
            hour = "12" if hour == "*" else hour
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
        self.init_ui()
        self.nmap_results = None
        self.scan_thread = None
        self.scheduler_dialog = SchedulerDialog(parent=self, main_window=self)
        self.vuln_dialog = VulnResultsDialog(parent=self, main_window=self)

    def init_ui(self):
        self.profile_combobox.addItems(["Intense scan", "Intense scan, all TCP ports", "Intense scan, no ping", "Ping scan", "Quick scan", "Intense Comprehensive Scan",
                                        "Quick scan plus", "Quick traceroute", "Regular scan", "Slow comprehensive scan", "TCP SYN Scan", "UDP SYN Scan", "Intense Scan, no Ping, Agressive"])
        self.vuln_scripts_combobox.addItems(["None", "vulners", "http-vulners-regex", "vulscan", "httprecon"])
        self.update_command()
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
        self.statusbar.showMessage("Status: Idle")

    def show_scheduler(self):
        self.scheduler_dialog.cron_preview.setPlainText(self.command_entry.text())
        self.scheduler_dialog.exec()
        
    def show_vulns(self, vuln_list):
        self.vuln_dialog.vuln_tabs.setTabText(0, vuln_list[0])
        self.vuln_dialog.output_list.addItems(vuln_list[1].splitlines())
        self.vuln_dialog.exec()
        
    def schedule_scan(self):
        command = self.command_entry.text()
        cron_time = "0 * * * *" #hourly
        user_cron = CronTab(user=True)
        job = user_cron.new(command=f'{command}| tee -a scan.txt', comment='nextgeNmap scheduled scan')
        job.setall(cron_time)
        user_cron.write()

    def start_scan(self):
        with tempfile.NamedTemporaryFile(delete=False) as temp_xml:
            self.output_xml = temp_xml.name

        self.process = QProcess()
        self.process.readyReadStandardOutput.connect(self.handle_stdout)
        self.process.readyReadStandardError.connect(self.handle_stderr)
        self.process.finished.connect(self.scan_finished)

        #command = f"nmap {self.arguments} -oX {output_xml} {self.target}"
        args = shlex.split(self.command_entry.text().strip())
        args[-1:-1] = ["-oX", self.output_xml]
        self.process.start(args[0], args[1:])
        self.cancel_button.setEnabled(True)
        self.statusbar.showMessage("Status: Running scan...")
        print(args)

    def handle_stdout(self):
        data = self.process.readAllStandardOutput().data().decode()
        self.update_output(data.strip())

    def handle_stderr(self):
        data = self.process.readAllStandardError().data().decode()
        self.update_output(data.strip())

    def scan_finished(self):
        self.nmap_results = PortScanner()
        with open(self.output_xml, 'r') as xml_file:
            try:
                self.nmap_results.analyse_nmap_xml_scan(xml_file.read())
                self.populate_ports_hosts_grid()
                self.cancel_button.setEnabled(False)
                self.statusbar.showMessage("Status: Idle")
            except PortScannerError as e:
                self.scan_error(str(e))
        os.remove(self.output_xml)
        self.process = None

    def terminate_scan(self):
        if self.process:
            #self.process.terminate()
            self.process.kill()
            self.process = None

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
        arguments = arguments.split()
        arguments = [arg for arg in arguments if not arg.startswith(arg_to_remove)]
        return " ".join(arguments)

    def update_command(self):
        profiles = {
            "Intense scan": "-T4 -A -v",
            "Intense scan, all TCP ports": "-p 1-65535 -T4 -A -v",
            "Intense scan, no ping": "-T4 -A -v -Pn",
            "Intense Scan, no Ping, Agressive": "-T4 -A -v -Pn --script 'default or (discovery and safe)'",
            "Intense Comprehensive Scan": "-p 1-65535 -T4 -A -v -PE -PP -PS80,443,21,22,25,3389 -PA3389 -PU40125 -PY -g 53 --script 'default or (discovery and safe)'",
            "Ping scan": "-sn",
            "Quick scan": "-T4 -F",
            "Quick scan plus": "-sV -T4 -O -F --version-light",
            "Quick traceroute": "-sn --traceroute",
            "Regular scan": "",
            "Slow comprehensive scan": "-sS -sU -T4 -A -v -PE -PP -PS80,443 -PA3389 -PU40125 -PY -g 53 --script \"default or (discovery and safe)\"",
            "UDP SYN Scan": "-sU -sS -T4 -A -v --top-ports 200",
            "TCP SYN Scan": "-sS -T4 -A -v --top-ports 200",
            "Custom": ""
        }

        vuln_scripts = {
            "None": "",
            "vulners": " -sV --script ./nse/vulners --script-args mincvss=7.5",
            "http-vulners-regex": " -sV --script ./nse/http/http-vulners-regex --script-args paths={\"/\"}",
            "vulscan": " -sV --script ./nse/vulscan/vulscan",
            "httprecon": " -sV --script ./nse/httprecon"
        }
        
        target = self.target_entry.text()
        profile = self.profile_combobox.currentText()
        vuln_script = self.vuln_scripts_combobox.currentText()

        self.vuln_scripts_combobox.currentIndexChanged.connect(self.update_command)
        if self.sender() == self.vuln_scripts_combobox:
            self.script_args_entry.setText("")

        if profile in profiles and vuln_script in vuln_scripts:
            arguments = profiles[profile]

            # Check if the selected profile has the -v argument
            if "-v" in arguments.split() and not self.verbose_checkbox.isChecked():
                self.verbose_checkbox.setChecked(True)
            
            if self.verbose_checkbox.isChecked():
                arguments = self.remove_argument(arguments, "-v")
                arguments += " -v"

            if self.port_range_entry.text():
                arguments = self.remove_argument(arguments, "-p")
                arguments += f" -p {self.port_range_entry.text()}"

            if vuln_script != "None":
                arguments = self.remove_argument(arguments, "-sV")
                if vuln_script == "vulners": self.script_args_entry.setPlaceholderText("mincvss=7.5 (vulners.nse)")
                elif vuln_script == "http-vulners-regex": self.script_args_entry.setPlaceholderText("paths={\"/\", \"/api/v1/\"} (http-vulners-regex.nse)")
                elif vuln_script == "vulscan": self.script_args_entry.setPlaceholderText("vulscanoutput=detailed,vulscandb=cve.csv (vulscan.nse)")
                elif vuln_script == "httprecon": self.script_args_entry.setPlaceholderText("httprecontoplist=500 (httprecon.nse)")

            script = vuln_scripts[vuln_script]
            script_args = f" --script-args {self.script_args_entry.text()}" if self.script_args_entry.text() else ""
            self.command_entry.setText(f"nmap {arguments}{script}{script_args} {target}")

    def update_output(self, text):
        self.nmap_output_text.appendPlainText(text)
        self.nmap_output_text.moveCursor(QTextCursor.MoveOperation.End)

    def scan_error(self, error_message):
        self.nmap_output_text.appendPlainText("Scan aborted: {}".format(error_message))

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


if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle(QStyleFactory.create('Fusion'))
    window = NextGeNmapGUI()
    window.show()
    sys.exit(app.exec())