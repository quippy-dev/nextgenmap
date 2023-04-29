import sys
import os
import tempfile
import subprocess
import psutil
import re
from PyQt6.QtWidgets import QApplication, QMainWindow, QStyleFactory, QTableWidgetItem, QDialog
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QTextCursor, QTextOption
from PyQt6.uic import loadUi
from nmap import PortScanner, PortScannerError
from crontab import CronTab

class NmapScanThread(QThread):
    output_received = pyqtSignal(str)
    scan_finished = pyqtSignal(PortScanner)
    scan_error = pyqtSignal(str)

    def __init__(self, target, arguments, parent=None):
        super().__init__(parent)
        self.target = target
        self.arguments = arguments
        self.process = None

    def run(self):
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            temp_filename = temp_file.name

        self.output_received.emit(f"\tnmap {self.arguments} {self.target}\n")

        command = f"nmap {self.arguments} -oX {temp_filename} {self.target}"
        self.process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, text=True)
        
        while (line := self.process.stderr.readline()):
            self.output_received.emit(line.strip())

        while (line := self.process.stdout.readline()):
            self.output_received.emit(line.strip())
        
        self.process.wait()
        nm = PortScanner()
        with open(temp_filename, 'r') as xml_file:
            try:
                nm.analyse_nmap_xml_scan(xml_file.read())
                self.scan_finished.emit(nm)
            except PortScannerError as e:
                self.scan_error.emit(str(e))
        os.remove(temp_filename)
        self.process = None

    def terminate(self):
        if self.process:
            process = psutil.Process(self.process.pid)
            for child_proc in process.children(recursive=True):
                child_proc.kill()
            process.kill()

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

    def parse_cron_schedule(self):
        # Provide a preview of the cron schedule
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
            for cb in [self.min_cbox, self.hour_cbox, self.date_cbox, self.month_cbox, self.day_cbox]: cb.setEnabled(True)
            self.toggling_custom_radio = False
            return

        minute, hour, date, month, day = cron_text.split()

        self.min_cbox.setCurrentIndex(int(minute)+1 if minute.isdigit() else 0)
        self.hour_cbox.setCurrentIndex(int(hour)+1 if hour.isdigit() else 0)
        self.date_cbox.setCurrentIndex(int(date)+1 if date.isdigit() else 0)
        self.month_cbox.setCurrentIndex(int(month)+1 if month.isdigit() else 0)
        self.day_cbox.setCurrentIndex(int(day)+1 if day.isdigit() else 0)

        self.min_cbox.setEnabled(',' not in minute and '/' not in minute and '-' not in minute)
        self.hour_cbox.setEnabled(',' not in hour and '/' not in hour and '-' not in hour)
        self.date_cbox.setEnabled(',' not in date and '/' not in date and '-' not in date)
        self.month_cbox.setEnabled(',' not in month and '/' not in month and '-' not in month)
        self.day_cbox.setEnabled(',' not in day and '/' not in day and '-' not in day)


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
            # rgon3: look here! this is where you can read the cron expression for the scheduler
            cron_expression = f"{minute} {hour} {date} {month} {day}"
            self.cron_schedule.setPlainText(cron_expression)

        self.updating_cron_schedule = False

class NextGeNmapGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        loadUi('nextgenmap.ui', self)
        self.init_ui()
        self.nm = None
        self.scan_thread = None
        self.scheduler_dialog = SchedulerDialog(parent=self, main_window=self)
        self.statusbar.showMessage("Status: Idle")

    def init_ui(self):
        self.profile_combobox.addItems(["Intense scan", "Intense scan, all TCP ports", "Intense scan, no ping", "Ping scan", "Quick scan", "Intense Comprehensive Scan",
                                        "Quick scan plus", "Quick traceroute", "Regular scan", "Slow comprehensive scan", "TCP SYN Scan", "UDP SYN Scan", "Intense Scan, no Ping, Agressive"])
        self.vuln_scripts_combobox.addItems(["None", "vulners", "http-vulners-regex", "vulscan", "httprecon"])
        self.update_command()
        self.scan_button.clicked.connect(self.start_scan)
        self.cancel_button.setEnabled(False)
        self.cancel_button.clicked.connect(self.cancel_scan)
        self.target_entry.textChanged.connect(self.update_command)
        self.target_entry.textChanged.connect(self.update_target)
        self.command_entry.textChanged.connect(self.update_target_from_command)
        self.profile_combobox.currentIndexChanged.connect(self.update_command)
        self.verbose_checkbox.stateChanged.connect(self.update_command)
        self.port_range_entry.textChanged.connect(self.update_command)
        self.vuln_scripts_combobox.currentIndexChanged.connect(self.update_command)
        self.schedule_button.clicked.connect(self.show_scheduler)

    def show_scheduler(self):
        self.scheduler_dialog.cron_preview.setPlainText(self.command_entry.text())
        self.scheduler_dialog.exec()
        
    def schedule_scan(self):
        command = self.command_entry.text()
        cron_time = "0 * * * *" #hourly
        user_cron = CronTab(user=True)
        job = user_cron.new(command=f'{command}| tee -a scan.txt', comment='nextgeNmap scheduled scan')
        job.setall(cron_time)
        user_cron.write()

    def start_scan(self):
        if self.scan_thread and self.scan_thread.isRunning():
            return

        command = self.command_entry.text().strip()
        if not command:
            return

        command_parts = command.split()
        if len(command_parts) < 3 or command_parts[-1].startswith("-"):
            return

        target = command_parts.pop()
        _ = command_parts.pop(0)
        arguments = " ".join(command_parts)

        self.scan_thread = NmapScanThread(target, arguments)
        self.scan_thread.output_received.connect(self.update_output)
        self.scan_thread.scan_finished.connect(self.scan_finished)
        self.scan_thread.scan_error.connect(self.scan_error)
        self.scan_thread.start()
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

    def cancel_scan(self):
        if self.scan_thread and self.scan_thread.isRunning():
            self.scan_thread.terminate()
            self.scan_thread.wait()
            self.scan_thread = None

    def update_output(self, text):
        self.nmap_output_text.appendPlainText(text)
        self.nmap_output_text.moveCursor(QTextCursor.MoveOperation.End)

    def scan_finished(self, nm):
        self.nm = nm
        self.populate_ports_hosts_grid()
        self.cancel_button.setEnabled(False)
        self.statusbar.showMessage("Status: Idle")

    def scan_error(self, error_message):
        self.nmap_output_text.appendPlainText("Scan aborted: {}".format(error_message))

    def populate_ports_hosts_grid(self):
        self.ports_hosts_table.setRowCount(0)
        row_num = 0
        for host in self.nm.all_hosts():
            if self.nm[host].state() == "up":
                for proto in self.nm[host].all_protocols():
                    lport = self.nm[host][proto].keys()
                    for port in lport:
                        status = self.nm[host][proto][port]["state"]
                        service = self.nm[host][proto][port]["name"]
                        version = self.nm[host][proto][port]["product"] + " " + self.nm[host][proto][port]["version"]
                        self.ports_hosts_table.insertRow(row_num)
                        self.ports_hosts_table.setItem(row_num, 0, QTableWidgetItem("✓"))
                        self.ports_hosts_table.setItem(row_num, 1, QTableWidgetItem(str(port)))
                        self.ports_hosts_table.setItem(row_num, 2, QTableWidgetItem(proto))
                        self.ports_hosts_table.setItem(row_num, 3, QTableWidgetItem(status))
                        self.ports_hosts_table.setItem(row_num, 4, QTableWidgetItem(service))
                        self.ports_hosts_table.setItem(row_num, 5, QTableWidgetItem(version))
                        row_num += 1
                        self.ports_hosts_table.resizeColumnsToContents()

                        # mitch: look here! this is where you can add the script output to the table
                        script_output = self.nm[host][proto][port].get('script', {})
                        if script_output:
                            for script_name, output in script_output.items():
                                print(f"Script: {script_name}")
                                print(f"Output:\n{output}")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle(QStyleFactory.create('Fusion'))
    window = NextGeNmapGUI()
    window.show()
    sys.exit(app.exec())