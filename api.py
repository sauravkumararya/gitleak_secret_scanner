from flask import Flask, request, jsonify
import subprocess
import os
import json
import shutil
import tempfile
import git

app = Flask(__name__)

# Path to GitLeaks executable
GITLEAKS_PATH = '/usr/local/bin/gitleaks'  # Update if the path differs

@app.route('/scan-repo', methods=['POST'])
def scan_repo():
    data = request.get_json()
    branch_name = data.get('branch_name')
    repo_link = data.get('repo_link')
    access_token = data.get('access_token')

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
            '-r', report_path,  # Use -r for report path
            '-f', 'json'  # Use -f for report format
        ]
        scan = subprocess.run(
            scan_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        if scan.returncode not in [0, 1]:  # Return codes 0 and 1 are valid
            return jsonify({'error': 'GitLeaks scan failed', 'details': scan.stderr}), 500

        # Read and parse the report
        if os.path.exists(report_path):
            with open(report_path) as f:
                report = json.load(f)
            if report:
                return jsonify({'result': report}), 200
            else:
                return jsonify({'result': "No secrets found."}), 200
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

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
