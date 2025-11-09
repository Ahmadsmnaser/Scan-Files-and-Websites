# 📦 Scan-Files-and-Websites — Chrome Security Extension

## 🚀 Overview
Scan-Files-and-Websites is a Chrome Extension designed to protect users by scanning downloaded files and visited websites through cloud security APIs.  
It supports real-time threat detection using the VirusTotal and MetaDefender APIs, and provides user-friendly alerts when risk is detected.

## 🎯 Features
- ✅ Scans downloaded files and URLs automatically  
- ✅ Calculates SHA-256 hash of files and sends to APIs  
- ✅ Uses both VirusTotal & MetaDefender for deep threat intelligence  
- ✅ Alerts user with a clear UI message: Safe / Dangerous / Scan Failed  
- ✅ Popup UI built with HTML/CSS/JS for easy user interaction  

## 🧠 Architecture

- Browser Download/URL Event → Extension Background Script → API Scan (VirusTotal, MetaDefender) → Popup UI → User Alert

- The extension leverages Chrome Extension APIs, asynchronous messaging between background & popup, and robust hash computation & API integration.
🛠️ Tech Stack

    - Languages: JavaScript, HTML, CSS

    - Browser Platform: Google Chrome Extension APIs

    - Security APIs: VirusTotal, MetaDefender

    - Tools: Git, Chrome DevTools, Webpack/ (if used)

    - Security Concepts: SHA-256 hashing, asynchronous API calls, user alert flows

## 📂 Project Structure

- Scan-Files-and-Websites/
│── manifest.json
│── background.js
│── popup.js
│── popup.html
│── popup.css
│── README.md
│── File and Website Security Scanner Chrome Extension.pdf

## 👤 My Role

 - Designed and implemented the extension logic to monitor downloads and URL visits

 - Implemented SHA-256 hash calculation for files

 - Integrated with VirusTotal & MetaDefender APIs for real-time scanning

 - Developed frontend popup UI & alerts for user interaction

 - Ensured code modularity and maintainability

## ✅ Example Usage

   - After installation, download a suspicious file (e.g., .exe)

   - The extension computes its hash and sends to both APIs

   - If threat found → popup displays “Dangerous file detected. Consider deleting.”

   - If safe → “No threats found. You’re protected.”

## 🔐 Security Notes

   - No file contents are sent; only SHA-256 hashes are transmitted.

   - API keys (if any) should be kept secret and not committed to the repository.

   - All user interactions are kept local to the browser extension.

   - Future versions will support encrypted storage of results and improved user privacy.

## 🔮 Future Improvements

   - Add database logging of scan results for analytics

   - Add UI for user to submit false-positives for review

   - Integrate more scanning APIs for extended protection

   - Add browser support for Firefox & Edge

## 🧑‍💻 Author

- Ahmad Naser
📧 Ahmadsmnaser@gmail.com

🔗 GitHub: https://github.com/Ahmadsmnaser
