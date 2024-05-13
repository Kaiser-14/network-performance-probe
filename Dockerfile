# Use an official Python runtime as the base image
FROM python:3.9

# Set the working directory in the container
WORKDIR /app

# Copy the Python code into the container
COPY . /app

# Install any Python dependencies
RUN pip install -r requirements.txt

EXPOSE 5001

#ENTRYPOINT ["python", "network_probe.py"]
#CMD ["python", "network_probe.py", "--live", "--verbose", "--host", "127.0.0.1", "--bandwidth", "--throughput", "--congestion", "--packet-loss", "--latency", "--jitter", "--prometheus", "5001"]
CMD ["python", "network_probe.py", "--live", "--verbose", "--host", "192.168.1.50", "--bandwidth", "--throughput", "--packet-loss", "--latency", "--prometheus", "5001"]