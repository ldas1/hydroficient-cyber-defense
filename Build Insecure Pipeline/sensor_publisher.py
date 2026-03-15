from http import client

import paho.mqtt.client as mqtt
import json
import random
import time
import ssl   # ADD THIS FOR TLS
from datetime import datetime, timezone

TLS_CONFIG = {                                      # ADD THIS
    "ca_certs": "certs/ca.pem",
    "broker_host": "localhost",
    "broker_port": 8883,
}

client = mqtt.Client(
    client_id="my-publisher",
    callback_api_version=CallbackAPIVersion.VERSION2
)

client.tls_set(                                     # ADD THIS
    ca_certs=TLS_CONFIG["ca_certs"],
    certfile=None,
    keyfile=None,
    cert_reqs=ssl.CERT_REQUIRED,
    tls_version=ssl.PROTOCOL_TLS,
)

client.connect(
    TLS_CONFIG["broker_host"],
    TLS_CONFIG["broker_port"],                      # CHANGE PORT
    keepalive=60
)

# ============================================
# CONFIGURE TLS - ADD THIS FOR TLS
# ============================================
client.tls_set(
    ca_certs=TLS_CONFIG["ca_certs"],    # Trust this CA
    certfile=None,                       # No client cert (server-only TLS)
    keyfile=None,                        # No client key
    cert_reqs=ssl.CERT_REQUIRED,         # Verify server certificate
    tls_version=ssl.PROTOCOL_TLS,        # Use modern TLS
)
# ============================================

class WaterSensorMQTT:
    """
    A water sensor that publishes readings to MQTT.
    """

# ============================================
    def __init__(self, device_id, location, broker="localhost", port=1883):
        self.device_id = device_id
        self.location = location
        self.counter = 0

        # MQTT setup
        self.client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
        self.client.connect(broker, port)
        self.client.loop_start()

        # Topic for this sensor
        self.topic = f"hydroficient/grandmarina/sensors/{self.location}/readings"

        # Base values for realistic variation
        self.base_pressure_up = 82
        self.base_pressure_down = 76
        self.base_flow = 40

    def get_reading(self):
        """Generate a sensor reading with realistic variation."""
        self.counter += 1
        return {
            "device_id": self.device_id,  # identity
            "location": self.location,    # context (optional but recommended)
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "counter": self.counter,
            "pressure_upstream": round(self.base_pressure_up + random.uniform(-2, 2), 1),
            "pressure_downstream": round(self.base_pressure_down + random.uniform(-2, 2), 1),
            "flow_rate": round(self.base_flow + random.uniform(-3, 3), 1),
        }

    def publish_reading(self):
        """Generate a reading and publish it to MQTT."""
        reading = self.get_reading()
        self.client.publish(self.topic, json.dumps(reading))
        return reading

    def run_continuous(self, interval=2):
        """Publish readings continuously at the specified interval."""
        print(f"Starting device: {self.device_id}")
        print(f"Location: {self.location}")
        print(f"Publishing to: {self.topic}")
        print(f"Interval: {interval} seconds")
        print("-" * 40)

        try:
            while True:
                reading = self.publish_reading()
                print(f"[{reading['counter']}] Pressure: {reading['pressure_upstream']}/{reading['pressure_downstream']} PSI, Flow: {reading['flow_rate']} gal/min")
                time.sleep(interval)
        except KeyboardInterrupt:
            print("\nSensor stopped.")
            self.client.loop_stop()
            self.client.disconnect()


# --------------------------------------------------
# RUN SENSOR (main program entry)
# --------------------------------------------------
if __name__ == "__main__":
    sensor = WaterSensorMQTT(
        device_id="GM-MAIN-001",
        location="main-building",
        broker="localhost",
        port=1883
    )

    sensor.run_continuous(interval=2)