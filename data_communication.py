from kafka import KafkaProducer
import pika
import requests
import json

def kafka_connection(kafka_server):
	producer = KafkaProducer(bootstrap_servers=kafka_server+':9092')

	return producer

def kafka_send(producer, json_data, topic):
	producer.send(topic, value=json_data.encode('utf-8'))

def rabbit_connection(rabbit_server):
	connection = pika.BlockingConnection(pika.ConnectionParameters(rabbit_server))
	channel = connection.channel()

	return channel, connection

def rabbit_send(channel, connection, json_data, queue):
	channel.basic_publish(exchange='', routing_key=queue, body=json_data)

	connection.close()

def api_send(json_data, api_url):
	headers = {'Content-Type': 'application/json'}
	response = requests.post(api_url, data=json_data, headers=headers)

	if response.status_code == 200:
		print("Data sent successfully")
	else:
		print(f"Failed to send data. Status code: {response.status_code}")
		print(response.text)
