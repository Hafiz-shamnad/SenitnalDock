# Sentinel Dock

Sentinel Dock is a powerful container security toolkit designed to secure Docker environments by providing essential features for vulnerability scanning, real-time monitoring, and container security. This project integrates **Trivy** for scanning vulnerabilities and continuously monitors Docker containers to detect potential security risks such as container escapes, misconfigurations, and resource usage anomalies.

## Features

- **Vulnerability Scanning with Trivy**: Automatically scan Docker images for vulnerabilities and generate a list of Common Vulnerabilities and Exposures (CVEs).
- **Real-time Monitoring**: Monitor Docker container metrics (such as CPU usage) and dynamically update the status on a web-based frontend.
- **Container Escape Detection**: Detect and alert on potential container escape attempts, improving overall security.
- **Configuration Hardening**: Provide guidelines to harden Docker container configurations for enhanced security.
- **PDF Report Generation**: Generate detailed PDF reports for security analysts, combining CVE data and mitigation suggestions from the National Vulnerability Database (NVD).
- **HTML Frontend**: Visualize container metrics and security scan results with an intuitive web interface.

## Installation

Follow these steps to set up Sentinel Dock on your local machine.

### Prerequisites

- **Docker**: Make sure Docker is installed and running on your machine.
- **Python**: Sentinel Dock is built using Python (Flask). Ensure you have Python 3.x installed.
- **Trivy**: Trivy is required for scanning Docker images for vulnerabilities.

### Steps

1. Clone the repository:

    ```bash
    git clone https://github.com/<your-username>/sentinel-dock.git
    cd sentinel-dock
    ```

2. Create a virtual environment and install dependencies:

    ```bash
    python3 -m venv venv
    source venv/bin/activate  # On Windows, use `venv\Scripts\activate`
    pip install -r requirements.txt
    ```

3. Install Trivy:

    ```bash
    brew install aquasecurity/trivy/trivy  # For macOS users
    sudo apt-get install trivy  # For Ubuntu users
    ```

4. Run the application:

    ```bash
    python app.py
    ```

    The web frontend will be accessible at [http://localhost:5000](http://localhost:5000).



Sentinel Dock will automatically scan the Docker image and display the results in the frontend.

### Viewing Metrics

Once the application is running, open a browser and navigate to [http://localhost:5000](http://localhost:5000). You’ll see real-time monitoring data such as CPU usage and a list of vulnerabilities.

### PDF Report

The system generates a PDF report with a list of vulnerabilities detected and mitigations from the National Vulnerability Database (NVD). The report is available from the frontend or can be triggered manually from the CLI.

## Roadmap

- **Database Integration**: Adding a database to store historical scan results and metrics.
- **Container Orchestration**: Integrate Kubernetes support for a more robust container orchestration environment.
- **Expanded Reporting**: Add more customizable report generation options.

## Contributing

1. Fork the repository.
2. Create a new branch (`git checkout -b feature-name`).
3. Commit your changes (`git commit -am 'Add new feature'`).
4. Push to the branch (`git push origin feature-name`).
5. Create a new Pull Request.

## License

Sentinel Dock is licensed under the Apache 2.0 License - see the [LICENSE](LICENSE) file for details.

## Acknowledgements

- **Trivy**: Used for vulnerability scanning in Docker containers.
- **Flask**: Used for the web framework to create the frontend.
- **Docker**: Used as the containerization platform for testing and running the security toolkit.
