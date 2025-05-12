# Use an official Python runtime as a parent image
FROM python:3.10-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# Set the working directory in the container
WORKDIR /app

# Install system dependencies that might be needed (e.g., for MySQL client)
# Uncomment the next line if you encounter issues connecting to MySQL
# RUN apt-get update && apt-get install -y --no-install-recommends default-mysql-client && rm -rf /var/lib/apt/lists/*

# Copy the requirements file into the container at /app
COPY requirements.txt .

# Install any needed packages specified in requirements.txt
# Using --no-cache-dir reduces image size
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code into the container at /app
# This includes the src directory and potentially other config files
COPY . .

# Make port 8080 available to the world outside this container
# Fly.io typically expects applications to listen on 8080
EXPOSE 8080

# Define the command to run the application
# Use gunicorn for production environments eventually, but start with Flask dev server
# For production with Fly.io, you might switch to:
CMD ["gunicorn", "--bind", ":8080", "--workers", "4", "wsgi:app"]
# CMD ["python", "src/main.py"]
