import sys
import os
import tempfile
import subprocess
import psutil
from nextgenmap_ui import Ui_MainWindow
from PyQt6.QtWidgets import QApplication, QMainWindow, QStyleFactory, QTableWidgetItem
from PyQt6.QtCore import QThread, pyqtSignal
from PyQt6.QtGui import QTextCursor
import nmap
from nmap import PortScanner, PortScannerError

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

        command = f"nmap {self.arguments} -oX {temp_filename} {self.target}"
        self.process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, text=True)
        
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

class NextGeNmapGUI(QMainWindow, Ui_MainWindow):
    def __init__(self):
        super().__init__()
        self.nm = None
        self.scan_thread = None
        self.setupUi(self)
        self.init_ui()

    def init_ui(self):
        self.profile_combobox.addItems(["Intense scan", "Intense scan, all TCP ports", "Intense scan, no ping", "Ping scan", "Quick scan", "Vulnerability Scan (Vulscan)", "Intense Comprehensive Scan",
                                        "Quick scan plus", "Quick traceroute", "Regular scan", "Slow comprehensive scan", "TCP SYN Scan", "UDP SYN Scan", "Intense Scan, no Ping, Agressive"])
        self.scan_button.clicked.connect(self.start_scan)
        self.cancel_button.setEnabled(False)
        self.cancel_button.clicked.connect(self.cancel_scan)
        self.target_entry.textChanged.connect(self.update_command)
        self.target_entry.textChanged.connect(self.update_target)
        self.command_entry.textChanged.connect(self.update_target_from_command)
        self.profile_combobox.currentIndexChanged.connect(self.update_command)
        self.update_command()

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

    def update_target(self):
        target = self.target_entry.text()
        command = self.command_entry.text()
        command_parts = command.split()
        if command_parts and command_parts[-1] == "{target}":
            command_parts[-1] = target
            self.command_entry.setText(" ".join(command_parts))

    def update_target_from_command(self):
        command = self.command_entry.text()
        command_parts = command.split()
        if len(command_parts) > 1:
            if command_parts[0] != "nmap":
                for i in range(len(command_parts)-1, -1, -1):
                    if not command_parts[i].startswith('-'):
                        self.target_entry.setText(command_parts[i])
                        return
        
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
            "Vulnerability Scan (Vulscan)": "--script=vulscan/vulscan.nse",
        }

        profile = self.profile_combobox.currentText()
        target = self.target_entry.text()

        if profile in profiles:
            arguments = profiles[profile]
            if target is not None:
                self.command_entry.setText(f"nmap {arguments} {target}")
        
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

    def scan_error(self, error_message):
        self.nmap_output_text.appendPlainText("Scan aborted.")

    def populate_ports_hosts_grid(self):
        self.ports_hosts_table.setRowCount(0)
        row_num = 0
        for host in self.nm.all_hosts():
            print (host)
            if self.nm[host].state() == "up":
                for proto in self.nm[host].all_protocols():
                    print (proto)
                    lport = self.nm[host][proto].keys()
                    for port in lport:
                        status = self.nm[host][proto][port]["state"]
                        service = self.nm[host][proto][port]["name"]
                        version = self.nm[host][proto][port]["product"] + " " + self.nm[host][proto][port]["version"]
                        self.ports_hosts_table.insertRow(row_num)
                        self.ports_hosts_table.setItem(row_num, 0, QTableWidgetItem("Host " + host))
                        self.ports_hosts_table.setItem(row_num, 1, QTableWidgetItem(str(port)))
                        self.ports_hosts_table.setItem(row_num, 2, QTableWidgetItem(proto))
                        self.ports_hosts_table.setItem(row_num, 3, QTableWidgetItem(status))
                        self.ports_hosts_table.setItem(row_num, 4, QTableWidgetItem(service))
                        self.ports_hosts_table.setItem(row_num, 5, QTableWidgetItem(version))
                        row_num += 1
                        self.ports_hosts_table.resizeColumnsToContents()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle(QStyleFactory.create('Fusion'))
    window = NextGeNmapGUI()
    window.show()
    sys.exit(app.exec())