import yara
import requests
import hashlib
import os
import pefile
import ssdeep
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import threading

# YARA rule file location
YARA_RULE_FILE = "/home/blackrock/Projects/Python/malwaredetect/windows_malware_rules.yar"

# VirusTotal API key (replace with your own)
VIRUSTOTAL_API_KEY = "1a8a1c8b6396b8e7a06aedb791d698e0ac41825ab609a1bf60ad56b5d60481de"

# YARA scanning function
def scan_with_yara(file_path):
    rules = yara.compile(filepaths={'rule': YARA_RULE_FILE})
    matches = rules.match(file_path)
    if matches:
        return "YARA detected potential malware."
    else:
        return "No malware detected by YARA."

# VirusTotal hash-checking function
def get_file_hash(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def check_virustotal(api_key, file_hash):
    url = f"https://www.virustotal.com/vtapi/v2/file/report?apikey={api_key}&resource={file_hash}"
    response = requests.get(url)
    vt_report = response.json()

    if vt_report['response_code'] == 1:
        positives = vt_report['positives']
        if positives > 0:
            return f"VirusTotal found {positives} antivirus engines flagged this file as malware."
        else:
            return "No malware detected by VirusTotal."
    else:
        return "File not found in VirusTotal's database."

# Heuristic check (file size)
def check_file_size(file_path):
    file_size = os.path.getsize(file_path)
    if file_size > 1000000:  # Flagging files larger than 1 MB
        return "Warning: This file is unusually large."
    else:
        return "File size seems normal."

# PE feature extraction for machine learning model
def extract_pe_features(file_path):
    try:
        pe = pefile.PE(file_path)
        
        # Extracting basic information
        file_size = os.path.getsize(file_path)
        entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        image_base = pe.OPTIONAL_HEADER.ImageBase
        number_of_sections = pe.FILE_HEADER.NumberOfSections
        checksum = pe.OPTIONAL_HEADER.CheckSum
        
        # Extract ssdeep fuzzy hash
        fuzzy_hash = ssdeep.hash_from_file(file_path)
        
        # Convert fuzzy hash to numeric (dummy value here, as it's complex)
        fuzzy_numeric = sum([ord(c) for c in fuzzy_hash]) % 100000
        
        return [file_size, entry_point, image_base, number_of_sections, checksum, fuzzy_numeric]
    except Exception as e:
        return None

# Full malware detection function
def detect_malware(file_path):
    results = []

    # VirusTotal hash-checking
    file_hash = get_file_hash(file_path)
    results.append(check_virustotal(VIRUSTOTAL_API_KEY, file_hash))
    
    # YARA signature detection
    results.append(scan_with_yara(file_path))
    
    # Heuristic analysis
    results.append(check_file_size(file_path))

    return "\n".join(results)

# Function to handle file selection and scanning
def browse_file():
    file_path = filedialog.askopenfilename(title="Select a File to Scan", filetypes=[("Executable files", "*.exe")])
    if file_path:
        scan_thread = threading.Thread(target=run_scan, args=(file_path,))
        scan_thread.start()

def run_scan(file_path):
    progress_bar.start()
    result = detect_malware(file_path)
    progress_bar.stop()
    messagebox.showinfo("Scan Results", result)

# GUI setup
def create_gui():
    root = tk.Tk()
    root.title("Malware Detection Tool")
    root.geometry("500x300")
    root.configure(bg="#f0f0f0")

    label = tk.Label(root, text="Select a file to scan for malware:", bg="#f0f0f0", font=("Arial", 14))
    label.pack(pady=20)

    scan_button = tk.Button(root, text="Browse", command=browse_file, bg="#007bff", fg="white", font=("Arial", 12), activebackground="#0056b3")
    scan_button.pack(pady=10)

    global progress_bar
    progress_bar = ttk.Progressbar(root, mode='indeterminate', length=300)
    progress_bar.pack(pady=20, fill=tk.X, padx=20)

    exit_button = tk.Button(root, text="Exit", command=root.quit, bg="#dc3545", fg="white", font=("Arial", 12), activebackground="#c82333")
    exit_button.pack(pady=10)

    # Adding an icon (optional)
    # root.iconbitmap("path_to_your_icon.ico")

    root.mainloop()

if __name__ == "__main__":
    create_gui()
