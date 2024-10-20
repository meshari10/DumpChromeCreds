# DumpChromeCreds

## Overview

`DumpChromeCreds.ps1` is a PowerShell script designed to extract and decrypt saved credentials from Google Chrome. It retrieves the user's login information, including usernames, passwords, and associated URLs, and exports this data to a CSV file.

## Features

- Extracts saved usernames and passwords from Google Chrome's SQLite database.
- Decrypts passwords encrypted with AES-GCM.
- Outputs the credentials in a formatted table in the console.
- Exports the credentials to a specified CSV file.

## Prerequisites
- **PowerShell 7**
- **PSSQLite Module**: The script will automatically install the `PSSQLite` module if it's not already available. If you want to manually install it, you can run the following command in PowerShell:
  ```powershell
  Install-Module -Name PSSQLite -Force -Scope CurrentUser
  ```

## Usage

1. **Clone the Repository (if applicable)**:
   ```bash
   git clone https://github.com/yourusername/DumpChromeCreds.git
   cd DumpChromeCreds
   ```

2. **Open PowerShell: Open a PowerShell terminal with administrative privileges.**
3. **Run the Script: Execute the script using the following command, replacing output.csv with your desired output file name:**
   ```powershell
    .\DumpChromeCreds.ps1 output.csv
   ```

## Reference
For more detailed information on extracting passwords from Chrome, you can refer to the article by James O'Neill: [Extracting Passwords and other secrets from Google Chrome, Microsoft Edge and other Chromium browsers with PowerShell](https://jhoneill.github.io/powershell/2020/11/23/Chrome-Passwords.html).

