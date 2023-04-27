import tkinter as tk
import nmap

class NmapGUI:
    def __init__(self):
        self.window = tk.Tk()
        self.window.title("nextgeNmap")

        # Target textbox
        self.target_label = tk.Label(self.window, text="Target:")
        self.target_label.grid(row=0, column=0)
        self.target_entry = tk.Entry(self.window)
        self.target_entry.grid(row=0, column=1)

        # Profile dropdown
        self.profile_label = tk.Label(self.window, text="Profile:")
        self.profile_label.grid(row=1, column=0)
        self.profile_var = tk.StringVar(self.window)
        self.profile_var.set("Intense scan, all TCP ports")
        self.profile_menu = tk.OptionMenu(self.window, self.profile_var, "Intense scan, all TCP ports")
        self.profile_menu.grid(row=1, column=1)

        # Scan and Cancel buttons
        self.scan_button = tk.Button(self.window, text="Scan", command=self.run_scan)
        self.scan_button.grid(row=2, column=0)
        self.cancel_button = tk.Button(self.window, text="Cancel", command=self.cancel_scan)
        self.cancel_button.grid(row=2, column=1)

        # Command textbox
        self.command_label = tk.Label(self.window, text="Command:")
        self.command_label.grid(row=3, column=0)
        self.command_entry = tk.Entry(self.window)
        self.command_entry.grid(row=3, column=1)
        self.command_entry.insert(0, "nmap -p 1-65535 -T4 -A -v")

    def run_scan(self):
        # Run nmap scan based on selected profile and target
        pass

    def cancel_scan(self):
        # Cancel running nmap scan
        pass

def main():
    app = NmapGUI()
    app.window.mainloop()

if __name__ == "__main__":
    main()
