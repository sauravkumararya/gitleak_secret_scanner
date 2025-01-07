from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
import subprocess
import os
import json
import shutil
import tempfile
import git
from datetime import datetime

app = Flask(__name__)

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///scans.db'  # Use SQLite for simplicity
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Define database model
class ScanReport(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    repo_url = db.Column(db.String(500), nullable=False)
    scan_date = db.Column(db.DateTime, default=datetime.utcnow)
    report = db.Column(db.Text, nullable=False)

# Create database tables
with app.app_context():
    db.create_all()

# Path to GitLeaks executable
GITLEAKS_PATH = '/usr/local/bin/gitleaks'  # Update this path if different

@app.route('/scan-repo', methods=['POST'])
def scan_repo():
    data = request.get_json()
    branch_name = data.get('branch_name')
    repo_link = data.get('repo_link')
    access_token = data.get('access_token')

    # Validate input
    if not all([branch_name, repo_link, access_token]):
        return jsonify({'error': 'Missing required parameters'}), 400

    # Create a temporary directory for cloning
    temp_dir = tempfile.mkdtemp()
    try:
        # Embed access token into the repo link for cloning
        repo_url = repo_link.replace('https://', f'https://{access_token}@')

        # Clone the repository
        repo = git.Repo.clone_from(repo_url, temp_dir, branch=branch_name, single_branch=True)

        # Run GitLeaks scan
        report_path = os.path.join(temp_dir, 'gitleaks_report.json')
        scan_cmd = [
            GITLEAKS_PATH,
            'detect',
            '--source', temp_dir,
          '--no-git',
            '-r', report_path,
            '-f', 'json'
        ]
        scan = subprocess.run(
            scan_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        if scan.returncode not in [0, 1]:  # Valid exit codes
            return jsonify({'error': 'GitLeaks scan failed', 'details': scan.stderr}), 500

        # Read and parse the report
        if os.path.exists(report_path):
            with open(report_path) as f:
                report = f.read()  # Save as raw JSON string
            # Save the report to the database
            new_report = ScanReport(repo_url=repo_link, report=report)
            db.session.add(new_report)
            db.session.commit()
            return jsonify({'result': json.loads(report)}), 200
        else:
            return jsonify({'error': 'GitLeaks report not found.'}), 500

    except git.exc.GitCommandError as e:
        return jsonify({'error': 'Failed to clone repository', 'details': str(e)}), 500
    except json.JSONDecodeError as e:
        return jsonify({'error': 'Failed to parse GitLeaks output', 'details': str(e)}), 500
    except Exception as e:
        return jsonify({'error': 'An unexpected error occurred', 'details': str(e)}), 500
    finally:
        # Clean up the temporary directory
        shutil.rmtree(temp_dir)

@app.route('/scan-reports', methods=['GET'])
def get_reports():
    """Get all scanned reports"""
    reports = ScanReport.query.all()
    results = []
    for report in reports:
        results.append({
            'id': report.id,
            'repo_url': report.repo_url,
            'scan_date': report.scan_date.isoformat(),
            'report': json.loads(report.report)  # Parse the JSON string
        })
    return jsonify(results), 200

@app.route('/scan-report/<int:report_id>', methods=['GET'])
def get_report(report_id):
    """Get a specific scanned report by ID"""
    report = ScanReport.query.get(report_id)
    if not report:
        return jsonify({'error': 'Report not found'}), 404

    result = {
        'id': report.id,
        'repo_url': report.repo_url,
        'scan_date': report.scan_date.isoformat(),
        'report': json.loads(report.report)  # Parse the JSON string
    }
    return jsonify(result), 200

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
