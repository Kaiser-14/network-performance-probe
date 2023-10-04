# Use an official Python runtime as the base image
FROM python:3.9

# Set the working directory in the container
WORKDIR /app

# Copy the Python code into the container
COPY . /app

# Install any Python dependencies
RUN pip install -r requirements.txt

ENTRYPOINT ["python", "network_probe.py"]