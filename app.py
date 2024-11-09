from flask import Flask, render_template, request, jsonify, send_file
import subprocess
import os
import uuid
import threading

app = Flask(__name__)

# Path for storing cloned repositories and reports
REPOS_DIR = os.path.join(os.getcwd(), "repos")
REPORTS_DIR = os.path.join(os.getcwd(), "reports")
os.makedirs(REPOS_DIR, exist_ok=True)
os.makedirs(REPORTS_DIR, exist_ok=True)

# Store scan status
SCAN_STATUS = {"status": "idle", "message": "", "report_path": ""}


def reset_scan_status():
    SCAN_STATUS.update({"status": "idle", "message": "", "report_path": ""})


def run_gitleaks_scan(git_url, access_token, unique_repo_name):
    try:
        # Clone repository
        repo_path = os.path.join(REPOS_DIR, unique_repo_name)
        clone_command = [
            "git",
            "clone",
            f"https://{access_token}@{git_url.replace('https://', '')}",
            repo_path,
        ]
        subprocess.run(clone_command, capture_output=True, check=True)

        # Generate a unique report filename
        report_filename = f"gitleaks-report-{uuid.uuid4()}.json"
        report_path = os.path.join(REPORTS_DIR, report_filename)

        # Run Gitleaks
        scan_command = [
            "gitleaks",
            "detect",
            "--source", repo_path,
            "--no-git",
            "--report-format", "json",
            "--report-path", report_path,
        ]
        result = subprocess.run(scan_command, capture_output=True, text=True, check=True)

        SCAN_STATUS.update({
            "status": "success",
            "message": "Scan completed successfully.",
            "report_path": report_path,
        })
    except subprocess.CalledProcessError as e:
        SCAN_STATUS.update({
            "status": "error",
            "message": f"Scan failed: {e.stderr}",
            "report_path": "",
        })
    finally:
        # Clean up cloned repository
        if os.path.exists(repo_path):
            subprocess.run(["rm", "-rf", repo_path])


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/start-scan', methods=['POST'])
def start_scan():
    reset_scan_status()
    data = request.form
    git_url = data.get("git_url")
    access_token = data.get("access_token")

    if not git_url or not access_token:
        return jsonify({"error": "Git URL and Access Token are required!"}), 400

    unique_repo_name = f"repo-{uuid.uuid4()}"
    threading.Thread(target=run_gitleaks_scan, args=(git_url, access_token, unique_repo_name)).start()

    return jsonify({"status": "Scan started"}), 200


@app.route('/scan-status', methods=['GET'])
def scan_status():
    return jsonify(SCAN_STATUS)


@app.route('/download-report', methods=['GET'])
def download_report():
    report_path = SCAN_STATUS.get("report_path")
    if not report_path or not os.path.isfile(report_path):
        return jsonify({"error": "No report available to download!"}), 400
    return send_file(report_path, as_attachment=True)


if __name__ == '__main__':
    app.run(debug=True)

