<h1 align="center">
  🛡️ Gitleaks Scanner - UI Based
</h1>

<p align="center">
  <img src="https://i.ibb.co/HrKp73M/Untitled-design-58.png" alt="Gitleaks Scanner Logo" width="200" height="200">
</p>

<p align="center">
  <strong>A powerful, user-friendly tool for detecting sensitive information in repositories, featuring a modern web interface.</strong>
</p>

---

<h2>🌟 Features</h2>
<ul>
  <li><strong>Easy-to-Use Web Interface:</strong> Perform scans directly from your browser, no CLI commands needed.</li>
  <li><strong>Comprehensive Scanning:</strong> Detect API keys, tokens, and other secrets in repositories.</li>
  <li><strong>Real-Time Reporting:</strong> Instantly view and download detailed scan reports.</li>
  <li><strong>Secure Integration:</strong> Uses private access tokens to securely clone repositories.</li>
  <li><strong>Support for Local and Remote Repositories:</strong> Scan public/private repositories or local folders.</li>
</ul>

---

<h2>⚙️ How It Works</h2>
<ol>
  <li><strong>Start the Container:</strong> 
    <pre><code>docker run -p 5000:5000 sauravkumararya/gitleaks-scanner-ui-based:latest</code></pre>
  </li>
  <li><strong>Access the Web Interface:</strong> Open your browser and navigate to <code>http://localhost:5000</code>.</li>
  <li><strong>Scan Your Repositories:</strong> Enter the repository URL and your access token, then start scanning.</li>
  <li><strong>View or Download the Report:</strong> See the detailed report directly in the UI or download it as a file.</li>
</ol>

---

<h2>🚀 Why Choose This?</h2>
<ul>
  <li>Designed for <strong>developers, security teams, and DevOps engineers</strong>.</li>
  <li>Perfect for integrating into <strong>CI/CD pipelines</strong>.</li>
  <li>Lightweight and portable; deployable anywhere using Docker.</li>
</ul>

---

<h2>🛠️ Tech Stack</h2>
<ul>
  <li><strong>Docker:</strong> Containerized for ease of deployment.</li>
  <li><strong>Flask:</strong> Lightweight backend framework.</li>
  <li><strong>Bootstrap:</strong> Responsive and modern UI design.</li>
  <li><strong>Gitleaks:</strong> Industry-standard secret detection tool.</li>
</ul>

---

<h2>📚 Getting Started</h2>

<h3>🔹 Option 1: Run with Docker</h3>
<ol>
  <li>Pull the Docker image:
    <pre><code>docker pull sauravkumararya/gitleaks-scanner-ui-based:latest</code></pre>
  </li>
  <li>Run the container:
    <pre><code>docker run -p 5000:5000 sauravkumararya/gitleaks-scanner-ui-based:latest</code></pre>
  </li>
  <li>Open the app in your browser and start scanning!</li>
</ol>

<h3>🔹 Option 2: Run Natively</h3>
<ol>
  <li><strong>Clone the Repository:</strong>
    <pre><code>git clone https://github.com/sauravkumararya/gitleak_secret_scanner.git</code></pre>
  </li>
  <li><strong>Navigate to the Project Directory:</strong>
    <pre><code>cd gitleak_secret_scanner</code></pre>
  </li>
  <li><strong>Set Up a Python Virtual Environment:</strong>
    <pre><code>python3 -m venv env</code>
    <code>source env/bin/activate  # Linux/Mac</code>
    <code>env\Scripts\activate  # Windows</code></pre>
  </li>
  <li><strong>Install Requirements:</strong>
    <pre><code>pip install -r requirements.txt</code></pre>
  </li>
  <li><strong>Run the Flask Application:</strong>
    <pre><code>flask run</code></pre>
    By default, the app will run on <code>http://127.0.0.1:5000</code>.
  </li>
</ol>

<h4>⚠️ Note:</h4>
<ul>
  <li>Ensure the <strong>gitleaks</strong> binary is installed and accessible in your system's PATH.</li>
  <li>If you don't have gitleaks, <a href="https://github.com/zricethezav/gitleaks/releases">download it here</a> and add it to your PATH.</li>
</ul>

---

<h2>🤝 Contributions & Support</h2>
<p>
  We welcome contributions and feature requests! Feel free to fork the repository or <a href="https://github.com/sauravkumararya/gitleak_secret_scanner/issues">open an issue</a> on GitHub.
</p>

---

<h3>👨‍💻 Author</h3>
<p>
  Developed by <strong>Saurav Kumar</strong>  
  📧 <a href="mailto:your-email@example.com">Email Support</a>  
  🌐 <a href="https://github.com/sauravkumararya">GitHub Profile</a>
</p>
