# 🔎 VirusTotal Scanner Web App

This is a simple web-based tool that allows users to scan **URLs** and **files** using the [VirusTotal API](https://www.virustotal.com/), and view the analysis results with an interactive UI.

## 🚀 Features

- ✅ Scan URLs and check for malicious or suspicious behavior.
- 📁 Upload and scan files up to 32MB.
- ⏳ Real-time polling of VirusTotal's analysis status.
- 📊 Visual progress bars and threat statistics.
- 🧠 Verdict system (Safe / Suspicious / Malicious).
- 🧾 Full JSON report viewer (expandable).


## 🧑‍💻 How to Use

1. Clone or download this repository.
2. Open `index.html` in your browser.
3. Enter a URL or choose a file.
4. Click **"Scan URL"** or **"Scan File"**.
5. Wait for the results to load and analyze.

## ⚙️ Setup

1. Get your free API key from [VirusTotal API Keys](https://www.virustotal.com/gui/user/apikey).
2. Replace the placeholder API key in `script.js`:

```js
const API_KEY = 'YOUR_API_KEY_HERE';
