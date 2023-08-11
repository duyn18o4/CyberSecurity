import tkinter as tk
from tkinter import messagebox, filedialog
import subprocess
import threading

def nmap_scan(cmd, text_output):
    try:
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        while True:
            output = process.stdout.readline()
            if not output:
                break
            text_update(text_output, output, False)
    except subprocess.CalledProcessError as e:
        text_update(text_output, f"Error executing nmap: {e}", False)

def text_update(output, content, delt):
    output.config(state=tk.NORMAL)
    if delt:
        output.delete(1.0, tk.END)
    output.insert(tk.END, f"{content}")
    output.see(tk.END)
    output.config(state=tk.DISABLED)

def val_update():
    entry_1 = entry_hosts.get()
    entry_2 = add_entry.get()
    scr = script_entry.get()
    s_val = service_val.get()
    o_val = os_val.get()
    t_val = tr_val.get()
    return entry_1, entry_2, scr, s_val, o_val, t_val

def port_update():
    port_cmd = ""
    range_ent = range_entry.get()
    if ports_range.get() == "r" and check_entry(range_ent):
        port_cmd += f" -p{range_ent}"
    else:
        port_cmd += " -p-"
    return port_cmd

def check_entry(ent):
    if (not ent) or (ent.isspace()):
        return False
    else:
        return True
    
def argument_update():  
    host, add, scripts, sv, ov, tv = val_update()
    cmd = "nmap"
    cmd += f"{' -sV' if sv else ''}{' -O' if ov else ''}{' --traceroute' if tv else ''}"
    if check_entry(scripts):
        cmd += f" --script={scripts}"
    if check_entry(add):
        cmd += f" {add}"
    cmd += f" {port_update()} {host}"
    return cmd
    
def on_scan_button_click():
    cmd = argument_update()
    text_update(cmd_disp, f"{cmd}", True)
    thread = threading.Thread(target=nmap_scan, args=(cmd, text_output))
    thread.start()

def help_display():
    try:
        with open("help.txt", "r") as file:
            help_text = file.read()
            help_window = tk.Toplevel(root)
            help_window.title("Help")
            help_disp = tk.Text(help_window, wrap=tk.WORD, width=100)
            help_disp.insert(tk.END, help_text)
            help_disp.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    except FileNotFoundError:
        messagebox.showerror("Error", "Help file not found.")

def save_file():
    text_to_save = text_output.get("1.0", "end-1c")
    file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt")])
    if file_path:
        try:
            with open(file_path, "w") as file:
                file.write(text_to_save)
            messagebox.showinfo("File saved", "Text saved to file successfully!")
        except Exception as e:
            messagebox.showerror("Error", f"Error saving the file: {e}")

#---------------------------------------------------------------------------
def create_UI(root):
    #   Host add
    label_hosts = tk.Label(root, text="Enter target hosts:")
    label_hosts.pack(pady=5)
    entry_hosts = tk.Entry(root, width=40)
    entry_hosts.pack()

    #   Scan type
    custom_options_frame = tk.LabelFrame(root, text="Custom Options", labelanchor='n')
    custom_options_frame.pack(padx=10, pady=5)
    scan_elements = tk.Frame(custom_options_frame)
    scan_elements.pack()
    scan_opt_ele = tk.Frame(scan_elements)
    scan_opt_ele.pack()
    service_val = tk.BooleanVar()
    os_val = tk.BooleanVar()
    tr_val = tk.BooleanVar()
    service_check = tk.Checkbutton(scan_opt_ele, text="Services", variable=service_val)
    service_check.pack(side=tk.LEFT)
    os_check = tk.Checkbutton(scan_opt_ele, text="OS", variable=os_val)
    os_check.pack(side=tk.LEFT)
    traceroute_check = tk.Checkbutton(scan_opt_ele, text="Trace route", variable=tr_val)
    traceroute_check.pack(side=tk.LEFT)

    ports_range = tk.StringVar()
    ports_range.set("a")
    label_port_range = tk.Label(scan_elements, text="Port range:")
    label_port_range.pack(anchor=tk.CENTER)
    port_frame = tk.Frame(scan_elements)
    port_frame.pack()
    all_port = tk.Radiobutton(port_frame, text="All ports", variable=ports_range, value="a")
    all_port.pack(side=tk.LEFT)
    range_chose = tk.Radiobutton(port_frame, text="Ports range:", variable=ports_range, value="r")
    range_chose.pack(side=tk.LEFT)
    range_entry = tk.Entry(port_frame, width=20)
    range_entry.pack(side=tk.LEFT, padx=10)
    #   Options input
    script_label = tk.Label(scan_elements, text="Scripts(comma seperated):")
    script_label.pack()
    script_entry = tk.Entry(scan_elements)
    script_entry.pack()
    add_opt = tk.Label(scan_elements, text="Additional options:")
    add_opt.pack()
    add_frame = tk.Frame(scan_elements)
    add_frame.pack()
    add_entry = tk.Entry(add_frame)
    add_entry.pack(side=tk.LEFT, padx=10, pady=(0,10))
    help_button = tk.Button(add_frame, text="Command list", command=help_display)
    help_button.pack(side=tk.LEFT, padx=10, pady=(0,10))

    #   Action Buttons
    button_frame = tk.Frame(root)
    button_frame.pack()
    scan_button = tk.Button(button_frame, text="Start", command=on_scan_button_click)
    scan_button.pack(side=tk.LEFT, padx=5)
    save_button = tk.Button(button_frame, text="Save result", command=save_file)
    save_button.pack(side=tk.LEFT, padx=5)

    #   Output
    cmd_label = tk.Label(root, text="Nmap command")
    cmd_label.pack()
    cmd_disp = tk.Text(root, wrap=tk.WORD, width=40, height=1)
    cmd_disp.config(state=tk.DISABLED)
    cmd_disp.pack(fill=tk.X, pady=(0,10), padx=40)
    output_label = tk.Label(root, text="Output")
    output_label.pack()
    text_output = tk.Text(root, wrap=tk.WORD)
    text_output.config(state=tk.DISABLED)
    text_output.pack(fill=tk.BOTH, expand=True, pady=(0,20), padx=20)

    #  Return widgets & values
    return entry_hosts, service_val, os_val, tr_val, ports_range, range_entry, script_entry, add_entry, cmd_disp, text_output


#--------------------------------------------------------------------------------------------------------------
root = tk.Tk()
root.title("Nmap Scan Tool")
root.geometry("900x800")
entry_hosts, service_val, os_val, tr_val, ports_range, range_entry, script_entry, add_entry, cmd_disp, text_output = create_UI(root)
root.mainloop()
