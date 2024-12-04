# Log File Analyzer 📊

A Python tool designed to analyze web server logs, providing insights into request patterns, frequently accessed endpoints, and detecting suspicious activity like potential brute-force login attempts.

---

## Features 🚀
- **IP Request Count:** Displays the number of requests per IP.
- **Top Endpoint Detection:** Identifies the most frequently accessed endpoint.
- **Suspicious Activity Detection:** Flags IP addresses with failed login attempts exceeding a configurable threshold.
- **CSV Report Generation:** Saves the analysis results to `log_analysis_results.csv`.
- **Error Handling:** Handles file errors, parsing issues, and unexpected exceptions gracefully.

---

## Installation & Usage 🛠️

### Prerequisites
- **Python 3.6+**

### Steps to Run
1. **Clone the Repository:**
   ```bash
   git clone https://github.com/username/log-file-analyzer.git
   cd log-file-analyze
2. **Run the Script:**
   ```bash
   python LogAnalysisScript.py

3. **Configure Threshold (Optional):**
   ```bash
   analyze_logs("logfile.txt", threshold=3)

### Results
## Results are saved to log_analysis_results.csv with sections for:

- **Requests per IP**
- **Most frequently accessed endpoint**
- **Suspicious activity detection**



   


