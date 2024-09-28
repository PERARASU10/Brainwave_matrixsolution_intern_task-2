# Brainwave_matrixsolution_intern_task-2

# Malware Detection Tool

A simple and efficient malware detection tool that combines YARA rules, VirusTotal database queries, and heuristic checks to analyze executable files for potential malware threats. This tool is designed for both security professionals and enthusiasts who want to explore malware detection techniques.

## Table of Contents

  - [Features](#features)
  - [Requirements](#requirements)
  - [Installation](#installation)
  - [Usage](#usage)
  - [Screenshots](#Screenshots)
  - [Contributing](#contributing)


## Features

  - **YARA Rule Scanning**: Utilize YARA rules to detect known malware signatures in executable files.
  - **VirusTotal Integration**: Check files against the VirusTotal database for additional malware detection insights.
  - **Heuristic Checks**: Implement heuristic methods, such as file size analysis, to flag potentially malicious files.
  - **User-Friendly GUI**: Simple graphical user interface for easy file scanning and result display.
  - **Multi-Threading**: Perform scans in a separate thread to keep the GUI responsive.

## Requirements

- Python 3.x
- Required Python packages:
  - `yara-python`
  - `requests`
  - `pefile`
  - `ssdeep`
  - `tkinter` (included with Python)
  - `pandas` (for data handling)

You can install the required packages using pip:

```
pip install yara-python requests pefile ssdeep pandas
```

## Installation

1. Clone this repository to your local machine:
 
    ```
    git clone https://github.com/PERARASU10/Brainwave_matrixsolution_intern_task-2.git
    ```
    
2. Navigate to the project directory:
    ```
      cd Brainwave_matrixsolution_intern_task-2
    ```

3. Ensure you have the required packages installed (see the Requirements section).

4. Place your YARA rules file in the project directory and update the path in the script if necessary.

5. (Optional) Obtain a VirusTotal API key and replace the placeholder in the code.

Here's a sample README file for your malware detection tool that utilizes YARA rules, the VirusTotal database, and heuristic checks:

markdown

## Screenshots
file:///home/blackrock/Pictures/Screenshots/Screenshot from 2024-09-28 21-48-29.png![image](https://github.com/user-attachments/assets/49bd70a3-9695-4706-bde6-d0cc215bd849)

file:///home/blackrock/Pictures/Screenshots/Screenshot from 2024-09-28 21-48-43.png![image](https://github.com/user-attachments/assets/f42af783-92aa-4e52-a916-7347dd4d546e)

file:///home/blackrock/Pictures/Screenshots/Screenshot from 2024-09-28 21-49-12.png![image](https://github.com/user-attachments/assets/37e01d8d-ef5c-4a13-8c16-5f59c0b1f967)


## Usage
Run the application:
```
        python malware_detection_tool.py
``` 
Click the "Browse" button to select an executable file (.exe) for scanning.

The tool will perform:

       YARA rule scanning
        
       VirusTotal hash-checking
        
       Heuristic checks (such as file size)

Once the scan is complete, results will be displayed in a message box.

## Contributing
Contributions are welcome! If you have suggestions or improvements, feel free to open an issue or submit a pull request.

Fork the repository.
Create your feature branch:

```
        git checkout -b feature/YourFeature
```
Commit your changes:
  ```
  git commit -m "Add some feature"
  ```
Push to the branch:
```
git push origin feature/YourFeature
```
Open a pull request.
