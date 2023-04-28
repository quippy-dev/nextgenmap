import sys
import os
import tempfile
import subprocess
import psutil
from PyQt5.QtWidgets import QApplication, QMainWindow, QHBoxLayout, QVBoxLayout, QTabWidget, QWidget, QLabel, QLineEdit, QComboBox, QPushButton, QTextEdit, QTableWidget, QTableWidgetItem
from PyQt5.QtCore import QThread, pyqtSignal
from PyQt5.QtGui import QTextCursor
from nmap import PortScanner, PortScannerError

class NmapScanThread(QThread):
    output_received = pyqtSignal(str)
    scan_finished = pyqtSignal(PortScanner)
    scan_error = pyqtSignal(str)

    def __init__(self, target, arguments, parent=None):
        super(NmapScanThread, self).__init__(parent)
        self.target = target
        self.arguments = arguments
        self.process = None  # Store the process

    def run(self):
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            temp_filename = temp_file.name
            temp_file.close()  # Close the file before running nmap

            command = f"nmap {self.arguments} -oX {temp_filename} {self.target}"
            print (command)
            self.process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, text=True)
            
            while True:
                line = self.process.stdout.readline()
                if not line:
                    break
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
            self.scan_finished.emit(nm)  # Emit the nm object
            self.process = None

    def terminate(self):
        if self.process is not None:
            process = psutil.Process(self.process.pid)
            for child_proc in process.children(recursive=True):
                child_proc.kill()
            process.kill()

class nextgeNmapGUI(QMainWindow):
    def __init__(self):
        super(nextgeNmapGUI, self).__init__()
        self.setWindowTitle("nextgeNmap")
        self.nm = None
        self.scan_thread = None
        self.init_ui()

    def init_ui(self):
        main_widget = QWidget(self)
        main_layout = QVBoxLayout(main_widget)

        self.target_entry = QLineEdit()
        self.profile_combobox = QComboBox()
        self.profile_combobox.addItems(["Intense scan", "Intense scan, all TCP ports", "Intense scan, no ping", "Ping scan", "Quick scan", "Quick scan plus", "Quick traceroute", "Regular scan", "Slow comprehensive scan"])
        self.scan_button = QPushButton("Scan")
        self.scan_button.clicked.connect(self.start_scan)
        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.setEnabled(False)
        self.cancel_button.clicked.connect(self.cancel_scan)
        self.nmap_output = QTextEdit()
        self.ports_hosts = QTableWidget()
        self.command_entry = QLineEdit()

        self.update_command()
        self.target_entry.textChanged.connect(self.update_command)
        self.target_entry.textChanged.connect(self.update_target)
        self.command_entry.textChanged.connect(self.update_target_from_command)
        self.profile_combobox.currentIndexChanged.connect(self.update_command)
        self.ports_hosts.setColumnCount(6)
        self.ports_hosts.setHorizontalHeaderLabels(["Status", "Port", "Protocol", "State", "Service", "Version"])
        
        target_layout = QHBoxLayout()
        target_layout.addWidget(QLabel("Target:"))
        target_layout.addWidget(self.target_entry)
        target_layout.addWidget(QLabel("Profile:"))
        target_layout.addWidget(self.profile_combobox)
        target_layout.addWidget(self.scan_button)
        target_layout.addWidget(self.cancel_button)
        main_layout.addLayout(target_layout)

        command_layout = QHBoxLayout()
        command_layout.addWidget(QLabel("Command:"))
        command_layout.addWidget(self.command_entry)
        main_layout.addLayout(command_layout)

        tabs = QTabWidget()
        tabs.addTab(self.nmap_output, "Nmap Output")
        tabs.addTab(self.ports_hosts, "Ports/Hosts")
        
        main_layout.addWidget(tabs)

        self.setCentralWidget(main_widget)
        self.setWindowTitle("nextgeNmap")
        self.setFixedSize(800, 600)

    def start_scan(self):
        if self.scan_thread and self.scan_thread.isRunning():
            return

        command = self.command_entry.text().strip()
        if not command:
            return

        command_parts = command.split()
        if len(command_parts) < 3 or command_parts[-1].startswith("-"):
            return

        target = command_parts.pop() # pop to remove target
        command_parts.pop(0) # pop to remove 'nmap'
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
        if command_parts:
            # Find the last non-option argument
            for i in range(len(command_parts)-1, -1, -1):
                if not command_parts[i].startswith('-'):
                    self.target_entry.setText(command_parts[i])
                    return
                
    def update_command(self):
        profiles = {
            "Intense scan": "-T4 -A -v",
            "Intense scan, all TCP ports": "-p 1-65535 -T4 -A -v",
            "Intense scan, no ping": "-T4 -A -v -Pn",
            "Ping scan": "-sn",
            "Quick scan": "-T4 -F",
            "Quick scan plus": "-sV -T4 -O -F --version-light",
            "Quick traceroute": "-sn --traceroute",
            "Regular scan": "",
            "Slow comprehensive scan": "-sS -sU -T4 -A -v -PE -PP -PS80,443 -PA3389 -PU40125 -PY -g 53 --script \"default or (discovery and safe)\""
        }

        profile = self.profile_combobox.currentText()
        target = self.target_entry.text()

        if profile in profiles:
            arguments = profiles[profile]
            self.command_entry.setText(f"nmap {arguments} {target}")
        
    def cancel_scan(self):
        if self.scan_thread and self.scan_thread.isRunning():
            self.scan_thread.terminate()
            self.scan_thread.wait()
            self.scan_thread = None

    def update_output(self, text):
        self.nmap_output.append(text)
        self.nmap_output.moveCursor(QTextCursor.End)
        #self.nmap_output.append(text)

    def scan_finished(self, nm):
        self.nm = nm  # Store the nm object
        self.populate_ports_hosts_grid()
        self.cancel_button.setEnabled(False)

    def scan_error(self, error_message):
        self.nmap_output.append("Scan aborted.")
        #self.nmap_output.append(f"Error: {error_message}")

    def populate_ports_hosts_grid(self):
        self.ports_hosts.setRowCount(0)
        row_num = 0
        for host in self.nm.all_hosts():
            for protocol in self.nm[host]['tcp'].keys():
                result = self.nm[host]['tcp'][protocol]
                self.ports_hosts.insertRow(row_num)
                self.ports_hosts.setItem(row_num, 0, QTableWidgetItem("-"))
                self.ports_hosts.setItem(row_num, 1, QTableWidgetItem(str(protocol)))
                self.ports_hosts.setItem(row_num, 2, QTableWidgetItem("tcp"))
                self.ports_hosts.setItem(row_num, 3, QTableWidgetItem(result['state']))
                self.ports_hosts.setItem(row_num, 4, QTableWidgetItem(result['name']))
                product_version = f"{result['product']} {result['version']}" if 'version' in result else result['product']
                self.ports_hosts.setItem(row_num, 5, QTableWidgetItem(product_version))
                #self.ports_hosts.setItem(row_num, 5, QTableWidgetItem(result['product']))
                row_num += 1

def main():
    app = QApplication(sys.argv)
    gui = nextgeNmapGUI()
    gui.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
