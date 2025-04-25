import json
import os
import shutil
import sys
from PyQt6.QtCore import Qt, QAbstractItemModel, QModelIndex, QProcess, QIODevice, QTemporaryFile, QThreadPool, QRunnable, QMutex
from PyQt6.QtWidgets import QWidget, QTreeView, QSplitter, QVBoxLayout, QLabel


BREW_SEARCHSPLOIT_PATHS = [
    "/opt/homebrew/bin/searchsploit",
    "/opt/homebrew/opt/exploitdb/bin/searchsploit",
    "/usr/local/bin/searchsploit",
    "/usr/local/opt/exploitdb/bin/searchsploit",
]


def _is_executable(path):
    return path and os.path.isfile(path) and os.access(path, os.X_OK)


def detect_searchsploit_binary():
    """Return (program, base_args) for SearchSploit execution."""

    env_path = os.getenv("SEARCHSPLOIT_PATH")
    if _is_executable(env_path):
        return env_path, []

    in_path = shutil.which("searchsploit") or shutil.which("searchsploit.exe")
    if in_path:
        return in_path, []

    for candidate in BREW_SEARCHSPLOIT_PATHS:
        if _is_executable(candidate):
            return candidate, []

    if sys.platform.startswith("win"):
        wsl_path = shutil.which("wsl")
        if wsl_path:
            distro = os.getenv("SEARCHSPLOIT_WSL_DISTRO")
            if distro:
                return wsl_path, ["-d", distro, "-e", "searchsploit"]
            return wsl_path, ["-e", "searchsploit"]

    raise FileNotFoundError(
        "SearchSploit was not found. Install exploitdb/searchsploit and ensure it is on PATH."
    )


def build_searchsploit_command(service):
    program, base_args = detect_searchsploit_binary()
    return program, base_args + ["-t", service, "-j"]


def process_searchsploit_results(searchsploit_results, host):
    processed_results = []

    if searchsploit_results:
        for exploit in searchsploit_results.get('RESULTS_EXPLOIT', []):
            processed_exploit = {
                'host': host,
                'type': f"exploit ({exploit['Type']})",
                'title': exploit['Title'],
                'path': exploit['Path'],
                'edb_id': exploit['EDB-ID'],
                'date_published': exploit['Date_Published'],
                'date_updated': exploit['Date_Updated'],
                'platform': exploit['Platform'],
                'author': exploit['Author'],
                'port': exploit['Port'],
                'verified': exploit['Verified'],
                'codes': exploit['Codes'],
                'application': exploit['Application'],
                'source': exploit['Source'],
            }
            processed_results.append(processed_exploit)
    else:
        print(f"No results found for host: {host}")
    print(f"Processed results: {processed_results}")
    return processed_results


def get_services_to_search(xml_root):
    services_to_search = {}

    for host in xml_root.findall("host"):
        host_address = host.find("address").get("addr")
        for service in host.findall(".//service"):
            product = service.get("product")
            version = service.get("version")

            if product and version:
                services_to_search.setdefault(host_address, set()).add(f"{product.lower()} {version}")
            elif product:
                services_to_search.setdefault(host_address, set()).add(product.lower())

    print(f"Services to search: {services_to_search}")
    return services_to_search


class TreeItem:
    def __init__(self, data, parent=None):
        self.parent_item = parent
        self.item_data = data
        self.child_items = []

    def append_child(self, child):
        self.child_items.append(child)

    def child(self, row):
        return self.child_items[row]

    def child_count(self):
        return len(self.child_items)

    def column_count(self):
        return len(self.item_data)

    def data(self, column):
        return self.item_data[column]

    def parent(self):
        return self.parent_item

    def row(self):
        if self.parent_item:
            return self.parent_item.child_items.index(self)
        return 0


class CustomModel(QAbstractItemModel):
    def __init__(self, data, parent=None):
        super(CustomModel, self).__init__(parent)
        self.root_item = TreeItem(("Host", "Type", "Title"))
        self.setup_model_data(data, self.root_item)

    def setup_model_data(self, data, parent):
        for item_data in data:
            item_values = (item_data["host"], item_data["type"], item_data["title"])
            item = TreeItem(item_values, parent)
            parent.append_child(item)
            if "children" in item_data:
                self.setup_model_data(item_data["children"], item)

    def columnCount(self, parent=QModelIndex()):
        if parent.isValid():
            return parent.internalPointer().column_count()
        return self.root_item.column_count()

    def data(self, index, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid():
            return None

        if role != Qt.ItemDataRole.DisplayRole:
            return None

        item = index.internalPointer()
        return item.data(index.column())

    def flags(self, index):
        if not index.isValid():
            return Qt.ItemFlag.NoItemFlags

        return Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
        if orientation == Qt.Orientation.Horizontal and role == Qt.ItemDataRole.DisplayRole:
            return self.root_item.data(section)

        return None

    def index(self, row, column, parent=QModelIndex()):
        if not self.hasIndex(row, column, parent):
            return QModelIndex()

        if not parent.isValid():
            parent_item = self.root_item
        else:
            parent_item = parent.internalPointer()

        child_item = parent_item.child(row)
        if child_item:
            return self.createIndex(row, column, child_item)
        return QModelIndex()

    def parent(self, index):
        if not index.isValid():
            return QModelIndex()

        child_item = index.internalPointer()
        parent_item = child_item.parent()

        if parent_item == self.root_item:
            return QModelIndex()

        return self.createIndex(parent_item.row(), 0, parent_item)

    def rowCount(self, parent=QModelIndex()):
        if parent.column() > 0:
            return 0

        if not parent.isValid():
            parent_item = self.root_item
        else:
            parent_item = parent.internalPointer()

        return parent_item.child_count()

    def update_data(self, data):
        self.beginResetModel()
        self.root_item = TreeItem(("Host", "Type", "Title"))
        self.setup_model_data(data, self.root_item)
        self.endResetModel()

    def get_item_details(self, index):
        if not index.isValid():
            return "Select an item to see details"

        item = index.internalPointer()
        details = f"Host: {item.data(0)}\ntype: {item.data(1)}\ntitle: {item.data(2)}"
        return details


class SearchSploitRunnable(QRunnable):
    def __init__(self, host, service, output_file, finished_callback, searchsploit_command):
        super().__init__()
        self.host = host
        self.service = service
        self.finished_callback = finished_callback
        self.output_file = output_file
        self.searchsploit_command = searchsploit_command

    def run(self):
        searchsploit_process = QProcess()
        searchsploit_process.setStandardOutputFile(self.output_file.fileName())

        program, base_args = self.searchsploit_command
        searchsploit_process.start(program, base_args + ["-t", self.service, "-j"])
        searchsploit_process.waitForFinished(-1)

        self.output_file.seek(0)
        searchsploit_json_data = self.output_file.readAll().data().decode('utf-8')

        try:
            searchsploit_json = json.loads(searchsploit_json_data)
        except json.JSONDecodeError as e:
            print(f"Error decoding JSON from searchsploit output: {e}")
            searchsploit_json = None

        self.finished_callback(self.host, searchsploit_json)


class SearchSploitWidget(QWidget):
    def __init__(self, parent=None):
        super(SearchSploitWidget, self).__init__(parent)

        self.thread_pool = QThreadPool()
        self.finished_counter = 0
        self.finished_counter_mutex = QMutex()
        self.searchsploit_command = self._detect_searchsploit_command()

        self.model = CustomModel(data=[])
        self.tree_view = QTreeView()
        self.tree_view.setModel(self.model)

        self.details_view = QLabel("Select an item to see details")
        self.status_label = QLabel()
        self.status_label.setWordWrap(True)
        self.status_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self._set_status_message()

        self.splitter = QSplitter()
        self.splitter.addWidget(self.tree_view)
        self.splitter.addWidget(self.details_view)

        layout = QVBoxLayout(self)
        layout.addWidget(self.status_label)
        layout.addWidget(self.splitter)

        self.tree_view.selectionModel().selectionChanged.connect(self.on_item_selected)

    def _detect_searchsploit_command(self):
        try:
            return detect_searchsploit_binary()
        except FileNotFoundError:
            return None

    def _set_status_message(self):
        if self.searchsploit_command:
            self.status_label.setText("SearchSploit detected. Ready to run checks.")
            self.status_label.setStyleSheet("")
            return

        if sys.platform.startswith("win"):
            message = (
                "SearchSploit is not available. Install ExploitDB's searchsploit or "
                "ensure WSL with a Linux distro is configured on Windows."
            )
        elif sys.platform == "darwin":
            message = (
                "SearchSploit is not available. Install it via Homebrew "
                "(brew install exploitdb) or set SEARCHSPLOIT_PATH."
            )
        else:
            message = (
                "SearchSploit is not available. Install ExploitDB's searchsploit and "
                "ensure it is on your PATH."
            )

        self.status_label.setText(message)
        self.status_label.setStyleSheet("color: #d08770;")

    def populate_data(self, data):
        self.model.update_data(data)

    def on_item_selected(self, selected, deselected):
        indexes = selected.indexes()
        if not indexes:
            return
        index = indexes[0]
        details = self.model.get_item_details(index)
        self.details_view.setText(details)

    def run_searchsploit(self, host, service, as_json=True, finished_callback=None):
        if not self.searchsploit_command:
            self._set_status_message()
            return

        searchsploit_output_file = QTemporaryFile("XXXXXX_searchsploit_output.json")
        searchsploit_output_file.setAutoRemove(True)
        if not searchsploit_output_file.open(QIODevice.OpenModeFlag.ReadWrite | QIODevice.OpenModeFlag.Text):
            print("Could not open searchsploit output file")
            return

        searchsploit_runnable = SearchSploitRunnable(
            host,
            service,
            searchsploit_output_file,
            finished_callback,
            self.searchsploit_command,
        )
        self.thread_pool.start(searchsploit_runnable)

    def run_searchsploit_on_services(self, services_to_search):
        if not self.searchsploit_command:
            self._set_status_message()
            return

        self.searchsploit_results = {}
        self.finished_counter = 0

        total_processes = sum(len(services) for services in services_to_search.values())
        data = []

        if total_processes == 0:
            self.populate_data(data)
            return

        def finished_callback(host, searchsploit_json):
            nonlocal data
            processed_results = process_searchsploit_results(searchsploit_json, host)
            print(f"Finished running SearchSploit on {host}...\n")
            data.extend(processed_results)

            self.finished_counter_mutex.lock()
            self.finished_counter += 1
            all_finished = self.finished_counter >= total_processes
            self.finished_counter_mutex.unlock()

            if all_finished:
                self.populate_data(data)

        for host, services in services_to_search.items():
            for service in services:
                self.run_searchsploit(host, service, as_json=True, finished_callback=finished_callback)
