# Use an official Python runtime as the base image
FROM python:3.9

# Set the working directory in the container
WORKDIR /app

# Copy the Python code into the container
COPY . /app

# Install any Python dependencies
RUN pip install -r requirements.txt

EXPOSE 5000 5001

CMD ["python", "network_probe.py", "--verbose", "--live", "--host", "127.0.0.1", "--throughput", "--latency", "--packet-loss", "--prometheus", "5001"]