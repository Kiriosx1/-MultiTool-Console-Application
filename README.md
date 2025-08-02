# 🧰 MultiTool Console Application

A powerful C++ console-based utility built by **kiriosx1**, designed to bundle multiple helpful tools and scripts into one user-friendly menu-driven system.

This application is built for **Windows systems** and includes tools for:
- 🧮 Calculations
- ⚙️ System utilities
- 🌐 Network tools
- 📁 File management
- 🎮 Fun & miscellaneous scripts

---

## 🚀 Features

### 📊 Calculators
- Basic arithmetic calculator
- Temperature converter
- BMI calculator
- Prime number checker
- Factorial calculator
- Base converter

### ⚙️ System Utilities
- Create restore points
- Show system info
- Check disk space
- Shutdown timer
- Wi-Fi manager
- Uninstaller launcher
- Windows Update checker
- List running processes

### 🌐 Network Tools
- Check internet connection
- Ping a website
- Download a file via URL

### 📁 File Utilities
- Create and read text files
- Clipboard history access
- Quick notes saving

### 🧪 Miscellaneous
- Number guessing game (via external script)
- Currency converter
- Random password generator (via external script)
- Text-to-speech using PowerShell

---

## 🖥️ Requirements

- ✅ Windows OS (tested on Windows 10/11)
- ✅ C++17 compatible compiler (e.g., MSVC / MinGW)
- ✅ Internet connection for download/ping features
- ✅ PowerShell installed (default on Windows)

---

## 🧑‍💻 Build & Run

### 🧰 Compile using MSVC:

cl multitool_reorganized.cpp /link shlwapi.lib urlmon.lib

---
# Or using g++ (MinGW):

g++ multitool_reorganized.cpp -o multitool.exe -lshlwapi -lurlmon

# Then run it:

multitool.exe

---

# 📂 Project Structure

multitool_reorganized.cpp     # Main source file

wordlist.txt                  # (Optional) For future tools like hash cracker

README.md                     # You're reading it!


# 📌 Notes
The password generator and number guessing game are downloaded and run dynamically from GitHub using PowerShell and Batch scripts.

Some features like Wi-Fi manager and restore points require admin privileges.

This project was built to be expandable — more modules coming soon!

---

# 📄 License
This project is open source and free to use. No license applied yet — default is MIT-style. You can add a LICENSE file to specify it.

---

# ✉️ Contact
📧 Business Email: kyros.businesss@gmail.com

---
Special thanks to the help of my friend Scooi you can check his work too on github 

https://github.com/SchooiCodes :) 
