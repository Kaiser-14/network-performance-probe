import argparse
import json
import logging
import random
import signal
import socket
import struct
import time
import threading
from datetime import datetime

from flask import Flask

app = Flask(__name__)
log = logging.getLogger('werkzeug')
log.setLevel(logging.CRITICAL)

import numpy as np
import psutil
from ping3 import ping

import data_communication

# Configure the logging system
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def send_icmp_echo_request(sock, dst_ip, icmp_id, icmp_seq):
	# ICMP Echo Request Type and Code
	icmp_type = 8
	icmp_code = 0

	# ICMP Header Checksum (0 for now, will be calculated later)
	icmp_checksum = 0

	# Generate the ICMP payload (some data for verification)
	_data = b'abcdefghijklmnopqrstuvwxyz' * 4

	# Calculate ICMP header checksum
	# icmp_header = struct.pack('!BBHHH', icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq)
	# icmp_checksum = calculate_checksum(icmp_header + data)
	# icmp_header = struct.pack('!BBHHH', icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq)

	# Generate the ICMP header without the checksum
	icmp_header = struct.pack('!BBHHH', icmp_type, icmp_code, 0, icmp_id, icmp_seq)
	# Calculate ICMP header checksum
	icmp_checksum = calculate_checksum(icmp_header + _data)
	# Update the ICMP header with the calculated checksum
	icmp_header = struct.pack('!BBHHH', icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq)

	# Send the ICMP Echo Request packet
	sock.sendto(icmp_header + _data, (dst_ip, 0))


def receive_icmp_echo_reply(sock, icmp_id, icmp_seq, timeout):
	start_time = time.time()
	while True:
		# Set socket timeout to avoid indefinite blocking
		_elapsed_time = time.time() - start_time
		remaining_time = timeout - _elapsed_time
		if remaining_time <= 0:
			break
		sock.settimeout(remaining_time)

		try:
			data, address = sock.recvfrom(1024)

			# Unpack the ICMP header
			icmp_header = data[20:28]
			icmp_type, icmp_code, _, received_id, received_seq = struct.unpack('!BBHHH', icmp_header)

			# Check if the received packet is an ICMP Echo Reply with the correct ID and Sequence
			if icmp_type == 0 and icmp_code == 0 and received_id == icmp_id and received_seq == icmp_seq:
				# logging.info(received_seq)
				rtt = time.time() - start_time
				return True, rtt

		except socket.timeout:
			break

	return False, None


def calculate_checksum(_data):
	# Calculate the ICMP header checksum
	checksum = 0
	for i in range(0, len(_data), 2):
		word = (_data[i] << 8) + _data[i + 1]
		checksum += word
		checksum = (checksum & 0xFFFF) + (checksum >> 16)
	checksum = ~checksum & 0xFFFF
	return checksum


def measure_packet_loss2(host, count=10, timeout=1):
	try:
		# Create a raw socket with ICMP protocol
		icmp_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)

		# Random ICMP ID and Sequence numbers for identification
		icmp_id = random.randint(0, 65535)
		packet_loss = 0

		for seq in range(count):
			send_icmp_echo_request(icmp_sock, host, icmp_id, seq)
			# time.sleep(1)
			if not receive_icmp_echo_reply(icmp_sock, icmp_id, seq, timeout):
				packet_loss += 1

		icmp_sock.close()

		packet_loss_rate = (packet_loss / count) * 100
		return packet_loss_rate

	except (socket.gaierror, PermissionError):
		return None  # Host is unreachable


def measure_bandwidth():
	# Extract network statistics from all the interfaces
	_network_interface_stats = psutil.net_if_stats()

	_net_dict = {}

	# Exclude not important interfaces from several deployment options
	excluded_interfaces = ['Loopback Pseudo-Interface 1', 'vEthernet (WSL)', 'lo']

	# Get the maximum available bandwidth
	for _interface, _data in _network_interface_stats.items():
		if _data.isup and _interface not in excluded_interfaces:
			# _net_dict[_interface] = {'value': _data.speed, 'metric': 'Mbps'}
			_net_dict[_interface] = _data.speed

	return _net_dict


def measure_throughput(host, port, duration, data_size_kb=1024):
	_data = b'X' * (data_size_kb * 1024)
	_measure = 'Mbps'

	with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
		s.connect((host, port))

		start_time = time.time()
		total_bytes_sent = 0

		while time.time() - start_time < duration:
			bytes_sent = s.send(_data)
			# bytes_sent = s.recv(1024)
			total_bytes_sent += bytes_sent

		_elapsed_time = time.time() - start_time
		if _measure == 'KB/s':
			throughput_kbps = (total_bytes_sent / 1024) / _elapsed_time  # KB/s
		else:
			throughput_mbps = (total_bytes_sent * 8e-6) / _elapsed_time  # Mbps

	return throughput_mbps, _measure


def measure_packet_loss(host, count=40, timeout=0.1):

	received_packets = 0

	for _ in range(count):
		response_time = ping(host, timeout)
		if response_time is not None:
			received_packets += 1

		time.sleep(0.05)  # Adjust the interval between pings as needed # FIXME: Consider latency

	packet_loss_rate = ((count - received_packets) / count) * 100

	return packet_loss_rate


def measure_latency(host, port):
	with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
		s.settimeout(5)  # Set a timeout for the connection attempt
		start_time = time.time()

		try:
			s.connect((host, port))
			_elapsed_time = time.time() - start_time
			latency_ms = _elapsed_time * 1000

		except socket.timeout:
			latency_ms = None  # Timeout occurred, host is unreachable

	return latency_ms


def measure_jitter(destination, count):

	rtt_packages = []

	for _ in range(count):
		ping_response = ping(destination, timeout=0.1)
		if ping_response:
			response_time = ping_response * 1000
			if response_time is not None:
				rtt_packages.append(response_time)

		time.sleep(0.1)  # Adjust the interval between pings as needed

	time_diffs = [rtt_packages[i] - rtt_packages[i - 1] for i in range(1, len(rtt_packages))]

	jitter = round(np.std(time_diffs), 2)

	return jitter


def measure_retransmission_rate(host, port, data_size_kb=1024, duration_sec=2):
	_data = b'X' * (data_size_kb * 1024)

	with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
		s.connect((host, port))

		start_time = time.time()
		total_packets_sent = 0
		retransmitted_packets = 0

		while time.time() - start_time < duration_sec:
			try:
				s.send(_data)
				total_packets_sent += 1
			except socket.error:
				retransmitted_packets += 1

		retransmission_rate = (retransmitted_packets / total_packets_sent) * 100
		return retransmission_rate


def calculate_congestion(duration):
	# Get the maximum available bandwidth for the network interface
	_network_interface_bw = measure_bandwidth()

	network_info = psutil.net_io_counters(pernic=True)
	network_info = {key: network_info[key]	for key in _network_interface_bw.keys()}

	# Sleep time to retrieve data
	time.sleep(duration)

	network_info_new = psutil.net_io_counters(pernic=True)
	network_info_new = {key: network_info_new[key] for key in _network_interface_bw.keys()}

	utilization = {}

	for interface in _network_interface_bw.keys():
		old_data = network_info[interface]
		new_data = network_info_new[interface]

		if not new_data:
			continue

		total_bytes = new_data.bytes_sent - old_data.bytes_sent + new_data.bytes_recv - old_data.bytes_recv

		utilization[interface] = round(
			(total_bytes * 1e-6 * 8 / duration / _network_interface_bw[interface]) * 100, 2)

	return utilization


def get_network_interface_statistics(interface_name):
	interfaces = psutil.net_if_stats()

	if interface_name in interfaces:
		interface_stats = interfaces[interface_name]
		return interface_stats
	else:
		return None


# Main function to perform on-demand measurements
def perform_measurements(
		verbose, host, port, duration, measure_bandwidth_flag, measure_throughput_flag=True,
		measure_packet_loss_flag=True, measure_latency_flag=True, measure_jitter_flag=True,
		measure_retransmission_rate_flag=True, measure_congestion_flag=True, measure_interface_stats_flag=True):
	start_time = time.time()

	# Initialize variables
	_measurements = {
		'bandwidth': {
		},
		'throughput': {
		},
		'congestion': {
		},
		'packet_loss': {
		},
		'latency': {
		},
		'jitter': {
		},
		'retransmission_rate': {
		},
		'interface_stats': {
		},
	}

	logging.info('---------------------------')
	logging.info('Performing network measurements...')
	logging.info(f'Target host: {host}')
	logging.info(f'Target port: {port}')
	logging.info('---------------------------')

	if measure_bandwidth_flag:
		# Get the available bandwidth for all the network interfaces
		start_bw_time = time.time()
		_network_interface_stats = measure_bandwidth()
		_measurements['bandwidth']['value'] = _network_interface_stats
		_measurements['bandwidth']['metric'] = 'Mbps'
		bw_elapsed_time = time.time() - start_bw_time

		interface = args.interface
		measure = 'Mbps'
		bandwidth = _network_interface_stats[interface]

		if verbose:
			logging.info(f'Measured Bandwidth on interface {interface}: {bandwidth:.2f} {measure}')
			logging.info(f'Time taken for Bandwidth measurement: {bw_elapsed_time:.4f} seconds')
			logging.info('---------------------------')

	if measure_throughput_flag:
		start_br_time = time.time()
		throughput, measure = measure_throughput(host, port, duration/2)
		_measurements['throughput']['value'] = float(f'{throughput:.2f}')
		_measurements['throughput']['metric'] = measure
		br_elapsed_time = time.time() - start_br_time
		if verbose:
			logging.info(f'Measured Throughput: {throughput:.2f} {measure}')
			logging.info(f'Time taken for Throughput measurement: {br_elapsed_time:.4f} seconds')
			logging.info('---------------------------')

	if measure_packet_loss_flag:
		start_loss_time = time.time()
		packet_loss = measure_packet_loss(host)
		_measurements['packet_loss']['value'] = packet_loss
		_measurements['packet_loss']['metric'] = '%'
		loss_elapsed_time = time.time() - start_loss_time
		if verbose:
			if packet_loss is not None:
				logging.info(f'Measured Packet Loss Rate: {packet_loss:.2f}%')
			else:
				logging.info('Packet loss measurement failed. Host may be unreachable.')
			logging.info(f'Time taken for Packet Loss measurement: {loss_elapsed_time:.4f} seconds')
			logging.info('---------------------------')

	if measure_latency_flag:
		start_latency_time = time.time()
		# latency, jitter = measure_latency(host)
		latency = measure_latency(host, port)
		# latency, rtt, jitter = measure_latency_rtt_jitter(host, port)
		_measurements['latency']['value'] = float(f'{latency:.2f}')
		_measurements['latency']['metric'] = 'ms'
		latency_elapsed_time = time.time() - start_latency_time
		if verbose:
			if latency is not None:
				logging.info(f'Measured Latency: {latency:.2f} ms')
			else:
				logging.info('Latency measurement failed. Host may be unreachable.')
			logging.info(f'Time taken for Latency measurement: {latency_elapsed_time:.4f} seconds')
			logging.info('---------------------------')

	if measure_jitter_flag:
		start_jitter_time = time.time()
		jitter = measure_jitter(host, count=10)
		_measurements['jitter']['value'] = jitter
		_measurements['jitter']['metric'] = 'ms'
		jitter_elapsed_time = time.time() - start_jitter_time
		if verbose:
			if jitter is not None:
				logging.info(f'Measured Jitter: {jitter:.2f} ms')
			else:
				logging.info('Jitter measurement failed. Host may be unreachable.')
			logging.info(f'Time taken for jitter measurement: {jitter_elapsed_time:.4f} seconds')
			logging.info('---------------------------')

	if measure_retransmission_rate_flag:
		start_rtxrate_time = time.time()
		retransmission_rate = measure_retransmission_rate(host, port)
		_measurements['retransmission_rate']['value'] = retransmission_rate
		_measurements['retransmission_rate']['metric'] = '%'
		rtxrate_elapsed_time = time.time() - start_rtxrate_time
		if verbose:
			logging.info(f'Measured Retransmission Rate: {retransmission_rate:.2f}%')
			logging.info(f'Time taken for Retransmission rate measurement: {rtxrate_elapsed_time:.4f} seconds')
			logging.info('---------------------------')

	if measure_congestion_flag:
		start_congestion_time = time.time()
		congestion = calculate_congestion(duration/2)
		_measurements['congestion']['value'] = congestion
		_measurements['congestion']['metric'] = '%'
		congestion_elapsed_time = time.time() - start_congestion_time
		if verbose:
			interface = args.interface
			logging.info(f"Network Utilization (%) on {interface}: {congestion[interface]:.2f}%")
			logging.info(f'Time taken for Network utilization measurement: {congestion_elapsed_time:.4f} seconds')
			logging.info('---------------------------')

	if measure_interface_stats_flag:
		interface_name = args.interface
		interface_stats = get_network_interface_statistics(interface_name)
		_measurements['interface_stats']['value'] = interface_stats
		if verbose:
			if interface_stats:
				logging.info(f'Network Interface: {interface_name}')
				logging.info(f'Bytes Sent: {interface_stats.bytes_sent}')
				logging.info(f'Bytes Received: {interface_stats.bytes_recv}')
				logging.info(f'Packets Sent: {interface_stats.packets_sent}')
				logging.info(f'Packets Received: {interface_stats.packets_recv}')
				logging.info(f'Errors: {interface_stats.errin + interface_stats.errout}')
				logging.info(f'Collisions: {interface_stats.collisions}')
			else:
				logging.info(f"Network interface '{interface_name}' not found.")
			logging.info('---------------------------')

	total_elapsed_time = time.time() - start_time
	if verbose:
		logging.info(f'Total time taken for all measurements: {total_elapsed_time:.4f} seconds')
		logging.info('---------------------------')

	# Filter out entries with 'None' values in the 'value' key
	_measurements = {key: value for key, value in _measurements.items() if value.get('value') is not None}

	return _measurements, total_elapsed_time


def run_procedure(_kafka_producer=None, _prometheus_metrics=None):
	try:
		measurements, elapsed_time = perform_measurements(
			args.verbose,
			args.remote_host,
			args.target_port,
			args.duration,
			measure_bandwidth_flag=args.bandwidth,
			measure_throughput_flag=args.throughput,
			measure_congestion_flag=args.congestion,
			measure_packet_loss_flag=args.packet_loss,
			measure_latency_flag=args.latency,
			measure_jitter_flag=args.jitter,
			measure_retransmission_rate_flag=args.retransmission_rate,  # FIXME: Check it
			measure_interface_stats_flag=args.interface_stats  # FIXME: Works better with congestion flag
		)

		# In case to retrieve information from origin host
		# hostname = socket.gethostname()
		# IPAddr = socket.gethostbyname(hostname)
		# logging.info("Your Computer Name is:" + hostname)
		# logging.info("Your Computer IP Address is:" + IPAddr)

		# Extract local IP
		s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		s.connect(('8.8.8.8', 1))  # connect() for UDP doesn't send packets
		local_ip_address = s.getsockname()[0]

		data['connection']['local'] = local_ip_address
		data['connection']['remote'] = args.remote_host
		data['connection']['port'] = args.target_port

		data['measurements'] = measurements

		data['timestamp'] = datetime.fromtimestamp(datetime.now().timestamp()).strftime("%d-%m-%Y, %H:%M:%S")
		data['total_time_taken'] = round(elapsed_time, 2)

		# Debug data extracted
		logging.debug(json.dumps(data, indent=4))

		# Apache Kafka
		if args.kafka:
			# producer = data_communication.kafka_connection(args.kafka[0])
			data_communication.kafka_send(_kafka_producer, json.dumps(data), args.kafka[1])

			logging.debug(f'Data transmitted to Kafka server.')

		# Rabbit MQ
		if args.rabbitmq:
			data_communication.rabbit_connection(args.rabbitmq[0])
			data_communication.rabbit_send(json.dumps(data), args.rabbit[1])

			logging.debug(f'Data transmitted to RabbitMQ broker.')

		# Rest API
		if args.api:
			data_communication.api_send(json.dumps(data), args.api)

			logging.debug(f'Data transmitted to Rest API')

		# Prometheus
		if args.prometheus:
			data_communication.prometheus_send(_prometheus_metrics, data)

		return data

	except PermissionError as e:
		logging.error('Error: Permission denied. Run the script with administrative privileges.')
	except Exception as e:
		logging.error(f'Error: {e}. Restart script for new measures.')
		time.sleep(60)

# Execute new loop based on external trigger
@app.route('/measure')
def trigger_measure():
	measurement_data = run_procedure(kafka_producer, prometheus_metrics)
	logging.info(f'Waiting trigger for next measure...')

	return json.dumps(measurement_data, indent=4), 200

# Handle user interruption
def signal_handler():
	logging.info('\nTraffic monitoring interrupted. Exiting...')
	exit(0)


# Main process
if __name__ == '__main__':
	# Data dictionary
	data = {
		'connection': {
			'local': None,
			'remote': None,
			'port': None,
		},
		'measurements': None,
		'timestamp': None,
		'total_time_taken': None
	}
	kafka_producer = None
	prometheus_metrics = None

	# Register the signal handler for KeyboardInterrupt (Ctrl+C)
	signal.signal(signal.SIGINT, signal_handler)

	# CLI commands
	parser = argparse.ArgumentParser(description='Network Measurement Script')
	parser.add_argument("--verbose", action="store_true", help='Print verbose output')
	parser.add_argument('--interface', dest='interface', required=False, default='eth0', help='Network interface (default: eth0)')
	parser.add_argument('--host', dest='remote_host', required=True, help='Specify the target host IP address')
	parser.add_argument('--port', dest='target_port', type=int, default=80, help='Specify the target port (default: 80)')
	parser.add_argument("--live", action="store_true", help="Enable live execution")
	parser.add_argument("--delay", type=int, default=30, help="Delay in seconds for live execution (default: 30s)")
	parser.add_argument('--duration', dest='duration', type=int, default=4, help='Test duration (default: 4)')
	parser.add_argument('--bandwidth', action='store_true', help='Enable bandwidth measurement')
	parser.add_argument('--throughput', action='store_true', help='Enable throughput measurement')
	parser.add_argument('--packet-loss', action='store_true', help='Enable packet loss rate measurement')
	parser.add_argument('--latency', action='store_true', help='Enable latency measurement')
	parser.add_argument('--jitter', action='store_true', help='Enable jitter measurement')
	parser.add_argument('--congestion', action='store_true', help='Enable network congestion measurement')
	parser.add_argument('--retransmission-rate', action='store_true', help='Enable retransmission rate measurement')
	parser.add_argument('--interface-stats', action='store_true', help='Enable network interface statistics measurement')
	parser.add_argument('--kafka', nargs=2, help='Kafka server address (e.g., localhost:9092) and topic')
	parser.add_argument('--rabbitmq', nargs=2, help='RabbitMQ server address and queue')
	parser.add_argument('--api', dest='api', type=str, help='API URL')
	parser.add_argument('--prometheus', dest='prometheus', type=int, help='Prometheus server')
	parser.add_argument('--flask', dest='flask', type=int, default=5000, help='Incoming HTTP request through the Flask server')
	args = parser.parse_args()

	# Enable connections
	if args.kafka:
		kafka_producer = data_communication.kafka_connection(args.kafka[0])
		logging.info(f'Kafka producer created on {args.kafka[0]}.')
	if args.prometheus:
		prometheus_thread = threading.Thread(target=data_communication.flask_start, args=(app, args.flask), daemon=True).start()
		prometheus_metrics = data_communication.prometheus_connection(args.prometheus)
		logging.info(f'Pushing metrics to Prometheus on port {args.prometheus}.')

	# Handle delays
	if args.live:
		# Infinite loop
		while True:
			run_procedure(kafka_producer, prometheus_metrics)
			logging.info(f'Waiting {args.delay} seconds for next measures...')
			time.sleep(args.delay)
	else:
		run_procedure(kafka_producer, prometheus_metrics)
		while True:
			logging.info(f'Waiting trigger for next measure...')
			time.sleep(120)
