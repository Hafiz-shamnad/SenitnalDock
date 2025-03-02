#!/bin/bash

# Exit immediately if a command exits with a non-zero status
set -e

# Define project directory
PROJECT_DIR="SenitnalDock"

echo "Creating project structure for $PROJECT_DIR..."

# Create the main directory and subdirectories
mkdir -p $PROJECT_DIR/{app/templates,app/static/css,app/static/js,trivy,migrations}

# Create required files
touch $PROJECT_DIR/{requirements.txt,config.py,run.py,README.md,.env}
touch $PROJECT_DIR/app/{__init__.py,routes.py,models.py,utils.py}
touch $PROJECT_DIR/app/templates/{base.html,dashboard.html}
touch $PROJECT_DIR/app/static/css/styles.css
touch $PROJECT_DIR/app/static/js/scripts.js
touch $PROJECT_DIR/trivy/{scan.py,cve_reporter.py}

# Add placeholders to README.md
cat <<EOL > $PROJECT_DIR/README.md
# Docker Security Toolkit

A Flask-based project to monitor Docker containers and generate CVE reports.

## Features
- Real-time Docker monitoring.
- Trivy integration for vulnerability scanning.
- Generate CVE reports with mitigations.

## Setup
Run the \`setup_project.sh\` script to initialize the structure.

## Future Enhancements
- Add database support to store scan results.
EOL

# Add .env placeholder
cat <<EOL > $PROJECT_DIR/.env
SECRET_KEY=your_secret_key
DATABASE_URL=sqlite:///db.sqlite3
EOL

# Add requirements
cat <<EOL > $PROJECT_DIR/requirements.txt
flask
flask-sqlalchemy
fpdf
requests
EOL

# Initialize a Git repository (optional)
cd $PROJECT_DIR
git init
echo "Initialized a Git repository in $PROJECT_DIR/"

# Completion message
echo "Project structure created successfully in $PROJECT_DIR!"
