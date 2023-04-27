import tkinter as tk
from tkinter import ttk
import nmap
import threading

class NmapGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("nextgeNmap")
        self.create_widgets()
        self.root.mainloop()

    def create_widgets(self):
        self.create_main_frame()
        self.create_top_row()
        self.create_command_entry()
        self.create_tabs()

    def create_main_frame(self):
        self.main_frame = ttk.Frame(self.root, padding="10 10 10 10")
        self.main_frame.grid(column=0, row=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        self.main_frame.columnconfigure(0, weight=1)
        self.main_frame.rowconfigure(0, weight=1)

    def create_top_row(self):
        target_label = ttk.Label(self.main_frame, text="Target:")
        target_label.grid(column=0, row=0, sticky=tk.W)

        self.target_entry = ttk.Entry(self.main_frame)
        self.target_entry.grid(column=1, row=0, sticky=(tk.W, tk.E))
        self.target_entry.bind("<KeyRelease>", self.update_command_entry)

        profile_label = ttk.Label(self.main_frame, text="Profile:")
        profile_label.grid(column=2, row=0)

        self.profile_combobox = ttk.Combobox(self.main_frame, values=[
            "Intense scan",
            "Intense scan, all TCP ports",
            "Intense scan, no ping",
            "Ping scan",
            "Quick scan",
            "Quick scan plus",
            "Quick traceroute",
            "Regular scan",
            "Slow comprehensive scan"
        ], state="readonly")
        self.profile_combobox.current(0)
        self.profile_combobox.bind("<<ComboboxSelected>>", self.update_command_entry)
        self.profile_combobox.grid(column=3, row=0, sticky=(tk.W, tk.E))

        self.scan_button = ttk.Button(self.main_frame, text="Scan", command=self.run_scan)
        self.scan_button.grid(column=4, row=0, sticky=tk.E)

        self.cancel_button = ttk.Button(self.main_frame, text="Cancel", command=self.cancel_scan)
        self.cancel_button.grid(column=5, row=0, sticky=tk.E)

        self.main_frame.grid_columnconfigure(1, weight=1)
        self.main_frame.grid_columnconfigure(3, weight=1)

    def update_command_entry(self, event=None):
        target = self.target_entry.get()
        profile = self.profile_combobox.get()
        command = f"nmap {target}"

        if profile == "Intense scan, all TCP ports":
            command = f"nmap -p 1-65535 -T4 -A -v {target}"
        elif profile == "Intense scan, no ping":
            command = f"nmap -T4 -A -v -Pn {target}"
        elif profile == "Ping scan":
            command = f"nmap -sn {target}"
        elif profile == "Quick scan":
            command = f"nmap -T4 -F {target}"
        elif profile == "Quick scan plus":
            command = f"nmap -sV -T4 -O -F --version-light {target}"
        elif profile == "Quick traceroute":
            command = f"nmap -sn --traceroute {target}"
        elif profile == "Regular scan":
            command = f"nmap {target}"
        elif profile == "Slow comprehensive scan":
            command = f"nmap -sS -sU -T4 -A -v -PE -PP -PS80,443 -PA3389 -PU40125 -PY -g 53 {target}"

        self.command_entry.delete(0, tk.END)
        self.command_entry.insert(0, command)

    def create_command_entry(self):
        self.command_entry = ttk.Entry(self.main_frame)
        self.command_entry.grid(column=0, row=1, columnspan=6, sticky=(tk.W, tk.E))

    def create_tabs(self):
        self.tabControl = ttk.Notebook(self.main_frame)
        
        self.nmap_output_tab = ttk.Frame(self.tabControl)
        self.tabControl.add(self.nmap_output_tab, text="Nmap Output")

        self.ports_hosts_tab = ttk.Frame(self.tabControl)
        self.tabControl.add(self.ports_hosts_tab, text="Ports/Hosts")
        
        self.tabControl.grid(column=0, row=2, columnspan=6, sticky=(tk.W, tk.E, tk.N, tk.S))
        self.create_nmap_output_tab()
        self.create_ports_hosts_tab()

    def create_nmap_output_tab(self):
        self.nmap_output_text = tk.Text(self.nmap_output_tab, wrap=tk.WORD, state="disabled")
        self.nmap_output_text.grid(column=0, row=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        scrollbar = ttk.Scrollbar(self.nmap_output_tab, orient=tk.VERTICAL, command=self.nmap_output_text.yview)
        scrollbar.grid(column=1, row=0, sticky=(tk.N, tk.S))
        self.nmap_output_text.configure(yscrollcommand=scrollbar.set)

    def create_ports_hosts_tab(self):
        self.ports_hosts_frame = ttk.Frame(self.ports_hosts_tab)
        self.ports_hosts_frame.grid(column=0, row=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Add the column headers
        headers = ["Status", "Port", "Protocol", "State", "Service", "Version"]
        for col_num, header in enumerate(headers):
            label = ttk.Label(self.ports_hosts_frame, text=header, relief=tk.RAISED, padding="5 5 5 5")
            label.grid(row=0, column=col_num, sticky="nsew")

    def run_scan(self):
        self.nmap_output_text.configure(state="normal")
        self.nmap_output_text.delete("1.0", tk.END)
        self.nmap_output_text.configure(state="disabled")

        target = self.target_entry.get()
        command = self.command_entry.get()
        parsed_command = command.split()

        self.nm = nmap.PortScanner()
        self.scan_thread = threading.Thread(target=self.scan_and_display, args=(target, parsed_command))
        self.scan_thread.daemon = True
        self.scan_thread.start()


    def cancel_scan(self):
        if self.scan_thread and self.scan_thread.is_alive():
            self.nm.process.stop()
            self.nmap_output_text.insert(tk.END, "\n\nScan canceled.")

    def scan_and_display(self, target, parsed_command):
        try:
            self.nm.scan(hosts=target, arguments=' '.join(parsed_command[1:]))
            self.display_nmap_output()
            self.root.after(1000, self.populate_ports_hosts_grid)
        except Exception as e:
            self.nmap_output_text.insert(tk.END, f"\n\nError: {str(e)}")

    def callback_result(self, host, scan_result):
        self.root.after(0, self.display_nmap_output, host, scan_result)

    def display_nmap_output(self):
        for host in self.nm.all_hosts():
            self.update_nmap_output(f"Host: {host}\n")
            
            for protocol in self.nm[host]['tcp'].keys():
                result = self.nm[host]['tcp'][protocol]
                self.update_nmap_output(f"Port: {protocol}\tState: {result['state']}\tService: {result['name']}\tVersion: {result['product']}\n")
                
            self.update_nmap_output("\n")
                    
    def update_nmap_output(self, text):
        self.nmap_output_text.configure(state="normal")
        self.nmap_output_text.insert(tk.END, text)
        self.nmap_output_text.see(tk.END)
        self.nmap_output_text.configure(state="disabled")

    def populate_ports_hosts_grid(self):
        # Clear the existing rows
        for widget in self.ports_hosts_frame.grid_slaves():
            if int(widget.grid_info()["row"]) > 0:
                widget.destroy()

        row_num = 1
        for host in self.nm.all_hosts():
            for protocol in self.nm[host]['tcp'].keys():
                result = self.nm[host]['tcp'][protocol]
                
                # if result['state'] == "open":
                #     status_icon = "green_circle_icon.png"  # Replace with an appropriate icon file
                #     status_label = ttk.Label(self.ports_hosts_frame, image=status_icon)
                # else:
                status_label = ttk.Label(self.ports_hosts_frame, text="-")
                status_label.grid(row=row_num, column=0)
                
                port_label = ttk.Label(self.ports_hosts_frame, text=protocol)
                port_label.grid(row=row_num, column=1)
                
                proto_label = ttk.Label(self.ports_hosts_frame, text="tcp")
                proto_label.grid(row=row_num, column=2)
                
                state_label = ttk.Label(self.ports_hosts_frame, text=result['state'])
                state_label.grid(row=row_num, column=3)
                
                service_label = ttk.Label(self.ports_hosts_frame, text=result['name'])
                service_label.grid(row=row_num, column=4)
                
                version_label = ttk.Label(self.ports_hosts_frame, text=result['product'])
                version_label.grid(row=row_num, column=5)
                
                row_num += 1

if __name__ == "__main__":
    app = NmapGUI()
