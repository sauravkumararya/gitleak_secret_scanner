# Use an official Python image as a base
FROM python:3.8-slim

# Metadata for the image
LABEL maintainer="Saurav Kumar <sauravkumararya@gmail.com>" \
      version="1.0" \
      description="Gitleaks scanner with Flask"

# Set the working directory inside the container
WORKDIR /app

# Copy the current directory contents into the container
COPY . /app

# Copy the gitleaks tarball from the host machine to the container
COPY gitleaks_8.21.2_linux_x64.tar.gz /tmp/gitleaks.tar.gz

# Install system dependencies and gitleaks binary
RUN apt-get update && apt-get install -y git && apt-get clean && \
    tar -xzf /tmp/gitleaks.tar.gz -C /usr/local/bin && \
    chmod +x /usr/local/bin/gitleaks && \
    rm /tmp/gitleaks.tar.gz

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Expose port 5000 for the Flask app
EXPOSE 5000

# Define environment variable for Flask
ENV FLASK_APP=app.py

# Run the Flask application
CMD ["flask", "run", "--host=0.0.0.0"]

