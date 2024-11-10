import os
import subprocess
import uuid
from flask import Flask, request, jsonify, render_template, send_from_directory

app = Flask(__name__)

# Directories for repositories and reports
REPO_DIR = os.path.join(os.getcwd(), 'repos')
REPORT_DIR = os.path.join(os.getcwd(), 'reports')

os.makedirs(REPO_DIR, exist_ok=True)
os.makedirs(REPORT_DIR, exist_ok=True)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/start-scan', methods=['POST'])
def start_scan():
    data = request.get_json()
    repo_url = data.get('repo_url')
    access_token = data.get('access_token')

    if not repo_url or not access_token:
        return jsonify({"error": "Repository URL and access token are required"}), 400

    # Clone the repository
    repo_id = f"repo-{uuid.uuid4()}"
    repo_path = os.path.join(REPO_DIR, repo_id)
    clone_command = [
        "git",
        "clone",
        f"https://{access_token}@{repo_url.split('https://')[-1]}",
        repo_path
    ]

    try:
        subprocess.run(clone_command, check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError as e:
        return jsonify({"error": f"Failed to clone repository: {e.stderr}"}), 500

    # Run Gitleaks scan
    report_filename = f"gitleaks-report-{uuid.uuid4()}.json"
    report_path = os.path.join(REPORT_DIR, report_filename)
    gitleaks_command = [
        "gitleaks",
        "detect",
        "--source", repo_path,
        "--no-git",
        "--report-format", "json",
        "--report-path", report_path
    ]

    try:
        subprocess.run(gitleaks_command, check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError:
        pass  # Ignore errors from gitleaks and return the report regardless

    # Always return the generated report
    return jsonify({
        "status": "completed",
        "message": "Scan completed.",
        "report_path": f"/reports/{report_filename}"
    })

@app.route('/reports/<filename>')
def download_report(filename):
    return send_from_directory(REPORT_DIR, filename, as_attachment=True)

if __name__ == "__main__":
    app.run(debug=True)

