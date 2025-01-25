import os
import hashlib
import datetime
import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import ttk
import magic  # To identify file type based on signature


class DigitalForensicsToolGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Digital Forensics Tool")
        self.root.geometry("700x500")
        self.root.resizable(False, False)

        # Styling
        self.style = ttk.Style()
        self.style.configure('TButton', font=('Helvetica', 10), width=20, padding=10)
        self.style.configure('TLabel', font=('Helvetica', 12))
        self.style.configure('TFrame', background='lightgray')

        # Create Widgets
        self.create_widgets()

    def create_widgets(self):
        # Title Label
        title_label = ttk.Label(self.root, text="Digital Forensics Tool", font=("Helvetica", 16, 'bold'))
        title_label.grid(row=0, column=0, columnspan=2, pady=20)

        # Buttons Frame
        button_frame = ttk.Frame(self.root)
        button_frame.grid(row=1, column=0, columnspan=2, padx=20, pady=10)

        # File Metadata Button
        file_button = ttk.Button(button_frame, text="Extract File Metadata", command=self.extract_file_metadata)
        file_button.grid(row=0, column=0, padx=10, pady=5)

        # File Hash Button
        hash_button = ttk.Button(button_frame, text="Calculate File Hashes", command=self.calculate_file_hashes)
        hash_button.grid(row=0, column=1, padx=10, pady=5)

        # Log Analysis Button
        logs_button = ttk.Button(button_frame, text="Analyze Log File", command=self.analyze_logs)
        logs_button.grid(row=1, column=0, padx=10, pady=5)

        # File Integrity Check Button
        integrity_button = ttk.Button(button_frame, text="File Integrity Checker", command=self.file_integrity_checker)
        integrity_button.grid(row=1, column=1, padx=10, pady=5)

        # Keyword Search Button
        keyword_search_button = ttk.Button(button_frame, text="Keyword Search in Logs", command=self.keyword_search_in_logs)
        keyword_search_button.grid(row=2, column=0, padx=10, pady=5)

        # File Type Identification Button
        file_type_button = ttk.Button(button_frame, text="Identify File Type", command=self.identify_file_type)
        file_type_button.grid(row=2, column=1, padx=10, pady=5)

        # Timestamp Analysis Button
        timestamp_button = ttk.Button(button_frame, text="Timestamp Analysis", command=self.timestamp_analysis)
        timestamp_button.grid(row=3, column=0, padx=10, pady=5)

        # Exit Button
        exit_button = ttk.Button(self.root, text="Exit", command=self.root.quit)
        exit_button.grid(row=4, column=0, columnspan=2, pady=20)

    # File Metadata Extraction
    def extract_file_metadata(self):
        file_path = filedialog.askopenfilename(title="Select a File")
        if not file_path:
            return
        
        metadata = self.get_file_metadata(file_path)
        metadata_display = "\n".join([f"{key}: {value}" for key, value in metadata.items()])
        messagebox.showinfo("File Metadata", metadata_display)

    def get_file_metadata(self, file_path):
        try:
            stats = os.stat(file_path)
            metadata = {
                "File Size (bytes)": stats.st_size,
                "Creation Time": datetime.datetime.fromtimestamp(stats.st_ctime).isoformat(),
                "Modification Time": datetime.datetime.fromtimestamp(stats.st_mtime).isoformat(),
                "Access Time": datetime.datetime.fromtimestamp(stats.st_atime).isoformat(),
            }
            return metadata
        except Exception as e:
            messagebox.showerror("Error", f"Error extracting metadata: {str(e)}")

    # File Hash Calculation
    def calculate_file_hashes(self):
        file_path = filedialog.askopenfilename(title="Select a File")
        if not file_path:
            return

        hashes = self.get_file_hashes(file_path)
        hash_display = "\n".join([f"{key}: {value}" for key, value in hashes.items()])
        messagebox.showinfo("File Hashes", hash_display)

    def get_file_hashes(self, file_path):
        try:
            with open(file_path, 'rb') as f:
                file_data = f.read()
                hashes = {
                    "MD5": hashlib.md5(file_data).hexdigest(),
                    "SHA-1": hashlib.sha1(file_data).hexdigest(),
                    "SHA-256": hashlib.sha256(file_data).hexdigest(),
                }
            return hashes
        except Exception as e:
            messagebox.showerror("Error", f"Error calculating hashes: {str(e)}")

    # Log File Analysis
    def analyze_logs(self):
        log_file = filedialog.askopenfilename(title="Select Log File", filetypes=(("Text files", "*.log"),))
        if not log_file:
            return

        logs = self.get_logs(log_file)
        logs_display = "\n".join(logs[:10])  # Display first 10 lines for simplicity

        messagebox.showinfo("Log Analysis", logs_display)

    def get_logs(self, log_file):
        try:
            with open(log_file, 'r') as f:
                logs = f.readlines()
            return logs
        except Exception as e:
            messagebox.showerror("Error", f"Error reading log file: {str(e)}")

    # File Integrity Checker
    def file_integrity_checker(self):
        file_path = filedialog.askopenfilename(title="Select a File")
        if not file_path:
            return

        known_hash = filedialog.askstring("Known Hash", "Enter the known hash to compare with:")
        if not known_hash:
            return

        file_hashes = self.get_file_hashes(file_path)
        if file_hashes["SHA-256"] == known_hash:
            messagebox.showinfo("Integrity Check", "File is intact.")
        else:
            messagebox.showerror("Integrity Check", "File has been modified!")

    # Keyword Search in Log Files
    def keyword_search_in_logs(self):
        log_file = filedialog.askopenfilename(title="Select Log File", filetypes=(("Text files", "*.log"),))
        if not log_file:
            return

        keyword = filedialog.askstring("Keyword", "Enter the keyword to search:")
        if not keyword:
            return

        logs = self.get_logs(log_file)
        result = [line for line in logs if keyword.lower() in line.lower()]

        if result:
            messagebox.showinfo("Search Results", "\n".join(result))
        else:
            messagebox.showinfo("Search Results", "No matches found.")

    # File Type Identification
    def identify_file_type(self):
        file_path = filedialog.askopenfilename(title="Select a File")
        if not file_path:
            return

        try:
            file_type = magic.from_file(file_path)
            messagebox.showinfo("File Type", f"The file type is: {file_type}")
        except Exception as e:
            messagebox.showerror("Error", f"Error identifying file type: {str(e)}")

    # Timestamp Analysis
    def timestamp_analysis(self):
        file_path = filedialog.askopenfilename(title="Select a File")
        if not file_path:
            return

        try:
            stats = os.stat(file_path)
            timestamps = {
                "Creation Time": datetime.datetime.fromtimestamp(stats.st_ctime).isoformat(),
                "Modification Time": datetime.datetime.fromtimestamp(stats.st_mtime).isoformat(),
                "Access Time": datetime.datetime.fromtimestamp(stats.st_atime).isoformat(),
            }
            timestamp_display = "\n".join([f"{key}: {value}" for key, value in timestamps.items()])
            messagebox.showinfo("Timestamp Analysis", timestamp_display)
        except Exception as e:
            messagebox.showerror("Error", f"Error analyzing timestamps: {str(e)}")


if __name__ == "__main__":
    root = tk.Tk()
    app = DigitalForensicsToolGUI(root)
    root.mainloop()
