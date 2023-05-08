import json
from PyQt6.QtCore import Qt, QAbstractItemModel, QModelIndex, QProcess, QIODevice, QTemporaryFile, QThreadPool, QRunnable, QMutex
from PyQt6.QtWidgets import QWidget, QTreeView, QSplitter, QVBoxLayout, QLabel


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
        self.root_item = TreeItem(("Host", "Type", "Title"))  # "Service",
        self.setup_model_data(data, self.root_item)

    def setup_model_data(self, data, parent):
        for item_data in data:
            item_values = (item_data["host"], item_data["type"], item_data["title"])  # item_data["service"],
            item = TreeItem(item_values, parent)
            parent.append_child(item)
            if "children" in item_data:
                self.setup_model_data(item_data["children"], item)

    # def setup_model_data(self, data, parent):
    #     for item_data in data:
    #         item = TreeItem(item_data, parent)
    #         parent.append_child(item)
    #         if "children" in item_data:
    #             self.setup_model_data(item_data["children"], item)

    # Implementations for QAbstractItemModel
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
        # Begin updating the model
        self.beginResetModel()

        # Clear the existing data
        self.root_item = TreeItem(("Host", "Type", "Title"))  # "Service",

        # Set up the new data
        self.setup_model_data(data, self.root_item)

        # Finish updating the model
        self.endResetModel()

    def get_item_details(self, index):
        if not index.isValid():
            return "Select an item to see details"

        item = index.internalPointer()
        # details = f"Host: {item.data(0)}\nService: {item.data(1)}\n# of exploits: {item.data(2)}\n# of shellcodes: {item.data(3)}"
        details = f"Host: {item.data(0)}\ntype: {item.data(1)}\ntitle: {item.data(2)}"
        return details


class SearchSploitRunnable(QRunnable):
    def __init__(self, host, service, output_file, finished_callback):
        super().__init__()
        self.host = host
        self.service = service
        self.finished_callback = finished_callback
        self.output_file = output_file

    def run(self):
        searchsploit_process = QProcess()
        searchsploit_process.setStandardOutputFile(self.output_file.fileName())

        searchsploit_command = ["wsl", ["-d", "kali-linux", "-e", "searchsploit", "-t", self.service, "-j"]]
        searchsploit_process.start(*searchsploit_command)
        searchsploit_process.waitForFinished(-1)

        # Read the JSON data from the temporary file
        self.output_file.seek(0)
        searchsploit_json_data = self.output_file.readAll().data().decode('utf-8')

        # Parse the JSON data
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

        # Create custom model and QTreeView with empty data
        self.model = CustomModel(data=[])
        self.tree_view = QTreeView()
        self.tree_view.setModel(self.model)

        # Create details view
        self.details_view = QLabel("Select an item to see details")

        # Create QSplitter and layout
        self.splitter = QSplitter()
        self.splitter.addWidget(self.tree_view)
        self.splitter.addWidget(self.details_view)

        layout = QVBoxLayout(self)
        layout.addWidget(self.splitter)

        # Connect signal
        self.tree_view.selectionModel().selectionChanged.connect(self.on_item_selected)

    def populate_data(self, data):
        self.model.update_data(data)

    def on_item_selected(self, selected, deselected):
        index = selected.indexes()[0]
        details = self.model.get_item_details(index)
        self.details_view.setText(details)

    def run_searchsploit(self, host, service, as_json=True, finished_callback=None):
        searchsploit_output_file = QTemporaryFile("XXXXXX_searchsploit_output.json")
        searchsploit_output_file.setAutoRemove(True)
        if not searchsploit_output_file.open(QIODevice.OpenModeFlag.ReadWrite | QIODevice.OpenModeFlag.Text):
            print("Could not open searchsploit output file")
            return

        searchsploit_runnable = SearchSploitRunnable(host, service, searchsploit_output_file, finished_callback)
        self.thread_pool.start(searchsploit_runnable)

    def process_searchsploit_results(self, searchsploit_results, host):
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

    def get_services_to_search(self, xml_root):
        services_to_search = {}

        for host in xml_root.findall("host"):
            host_address = host.find("address").get("addr")
            for service in host.findall(".//service"):
                name = service.get("name")
                product = service.get("product")
                version = service.get("version")

                if product and version:
                    services_to_search.setdefault(host_address, set()).add(f"{product.lower()} {version}")
                elif product:
                    services_to_search.setdefault(host_address, set()).add(product.lower())
                # elif name:
                #     services_to_search.setdefault(host_address, set()).add(name.lower())

        print(f"Services to search: {services_to_search}")
        return services_to_search

    def run_searchsploit_on_services(self, services_to_search):
        self.searchsploit_results = {}

        total_processes = sum(len(services) for services in services_to_search.values())
        data = []

        def finished_callback(host, searchsploit_json):
            nonlocal data
            processed_results = self.process_searchsploit_results(searchsploit_json, host)
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
