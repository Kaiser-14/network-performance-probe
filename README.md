# Network Performance Probe

![Python](https://img.shields.io/badge/Python-3.x-blue.svg)

A Python-based network performance probe that measures various metrics using socket communication.

## Table of Contents
- [Introduction](#introduction)
- [Features](#features)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
- [Usage](#usage)
- [Options](#options)
- [Contributing](#contributing)
- [License](#license)

## Introduction

This network performance probe is designed to measure various network metrics using socket communication. It allows you to gather critical information about network performance, such as bandwidth, throughput, latency, packet loss rate, jitter, retransmission rate, and network interface statistics.

## Features

- Measures multiple network performance metrics.
- Easy-to-use command-line interface.
- Customizable test duration, target host, and port.
- Detailed verbose output option.

## Getting Started

### Prerequisites

- Python 3.x
- Configure a web server like Apache or Nginx, as port 80 is the default port for HTTP traffic. For example, on Ubuntu, you can follow these steps:
  - Install Apache2 using the `apt` package manager:

    ```bash
    sudo apt update
    sudo apt install apache2
    ```

  - Start and enable Apache:

    ```bash
    sudo systemctl start apache2
    sudo systemctl enable apache2
    ```

  - Check the firewall to allow incoming HTTP traffic:

    ```bash
    sudo ufw allow 80/tcp
    ```

  - Verify that Apache is properly listening on port 80:

    ```bash
    sudo ss -tuln | grep :80
    ```

### Installation

1. Clone this repository to your local machine:

   ```bash
   git clone https://github.com/your-username/network-performance-probe.git
   ```
   
2. Navigate to the project directory:

   ```bash
   cd network-performance-probe
   ```

3. Install the required dependencies:

   ```bash
   pip install -r requirements.txt
   ```

## Usage

To measure network performance, run the following command:

   ```bash
   python network_probe.py --host <target_host> [options]
   ```

Replace <target_host> with the IP address or hostname of the target you want to measure.

## Options

- '--verbose': Print verbose output.
- '--host <target_host>': Specify the target host IP address (required).
- '--port <target_port>': Specify the target port (default: 80).
- '--duration <duration>': Test duration in seconds (default: 4).
- '--bandwidth': Enable bandwidth measurement.
- '--throughput': Enable throughput measurement.
- '--packet-loss': Enable packet loss rate measurement.
- '--latency': Enable latency measurement.
- '--jitter': Enable jitter measurement.
- '--congestion': Enable network congestion measurement.
- '--retransmission-rate': Enable retransmission rate measurement. [NOT WORKING]
- '--interface-stats': Enable network interface statistics measurement. [NOT WORKING]

Example usage:

   ```bash
   python network_probe.py --host 192.168.1.291 --port 80 --bandwidth --latency --congestion --verbose
   ```

On Docker

   ```bash
   docker build -t network-probe:latest .
   docker run network-probe:latest --verbose --host 192.168.1.291 --bandwidth --throughput --packet-loss --latency --jitter --congestion
   ```

## License

[//]: # (This project is licensed under the MIT License - see the LICENSE file for details.)