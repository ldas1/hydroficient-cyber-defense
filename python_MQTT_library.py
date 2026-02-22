##Start mosquitto: /opt/homebrew/opt/mosquitto/sbin/mosquitto -v
##See if its connected: lsof -i :1883
##  kill 64340
####Check if its connected: lsof -1 :1883


import paho.mqtt.client as mqtt
import json

# Create client and connect
client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
client.connect("localhost", 1883)
client.loop_start()

# Create a message (usually JSON)
message = {
    "device_id": "GM-HYDROLOGIC-01",
    "pressure": 82.3,
    "flow_rate": 41.2
}

# Publish to a topic
client.publish("hydroficient/grandmarina/sensors/main-building", json.dumps(message))

print("Message sent!")


# import and connect
import paho.mqtt.client as mqtt

client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
client.connect("localhost", 1883)
print("Connected!")

#send message
import paho.mqtt.client as mqtt

client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
client.connect("localhost", 1883)

client.loop_start()

client.publish("hydroficient/grandmarina/test/hello", "Hello from Python!")
print("Message sent!")

#Step 3: Send JSON data
import paho.mqtt.client as mqtt
import json

client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
client.connect("localhost", 1883)
client.loop_start()

reading = {"pressure": 82.3, "flow": 41.2}
client.publish("hydroficient/grandmarina/test/sensor", json.dumps(reading))
print(f"Sent: {reading}")

#Step 4: Add timestamps and loop
import paho.mqtt.client as mqtt
import json
import time
from datetime import datetime, timezone

client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
client.connect("localhost", 1883)
client.loop_start()

for i in range(5):
    reading = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "pressure": 82.3,
        "flow": 41.2
    }
    client.publish("hydroficient/grandmarina/test/sensor", json.dumps(reading))

    print(f"Sent reading {i+1}")
    time.sleep(2)

###water sensor that publishes readings to mqtt
import paho.mqtt.client as mqtt
import json
import random
import time
from datetime import datetime, timezone

class WaterSensorMQTT:
    """
    A water sensor that publishes readings to MQTT.
    """

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

####basic subscriber
import paho.mqtt.client as mqtt
import json

def on_connect(client, userdata, flags, reason_code, properties):
    print("Connected to Grand Marina MQTT Broker")
    print("=" * 50)
    # Subscribe to all Grand Marina topics
    client.subscribe("hydroficient/grandmarina/#")

def on_message(client, userdata, msg):
    print(f"{msg.topic}: {msg.payload.decode()}")

client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
client.on_connect = on_connect
client.on_message = on_message

client.connect("localhost", 1883)
client.loop_forever()


#####dashboard
import paho.mqtt.client as mqtt
import json
from datetime import datetime

def on_connect(client, userdata, flags, reason_code, properties):
    print("\n" + "=" * 60)
    print("  GRAND MARINA WATER MONITORING DASHBOARD")
    print("  Connected at:", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    print("=" * 60)
    client.subscribe("hydroficient/grandmarina/#")

def on_message(client, userdata, msg):
    try:
        data = json.loads(msg.payload.decode())
        display_reading(data)
    except json.JSONDecodeError:
        # Non-JSON message (maybe a command or alert)
        print(f"\n[RAW] {msg.topic}")
        print(f"      {msg.payload.decode()}")

def display_reading(data):
    """Format and display a sensor reading."""
    print(f"\n{'─' * 40}")
    print(f"  Location:  {data.get('location', 'Unknown')}")
    print(f"  Device ID: {data.get('device_id', 'Unknown')}")
    print(f"  Time:      {data.get('timestamp', 'N/A')}")
    print(f"  Count:     #{data.get('counter', 0)}")
    print(f"{'─' * 40}")

    # Pressure readings
    up = data.get('pressure_upstream', 0)
    down = data.get('pressure_downstream', 0)
    print(f"  Pressure (upstream):   {up:6.1f} PSI")
    print(f"  Pressure (downstream): {down:6.1f} PSI")

    # Pressure differential (can indicate blockage)
    diff = up - down
    print(f"  Pressure differential: {diff:6.1f} PSI")

    # Flow rate
    flow = data.get('flow_rate', 0)
    print(f"  Flow rate:             {flow:6.1f} gal/min")

# Create and configure client
client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
client.on_connect = on_connect
client.on_message = on_message

# Connect and run
print("Connecting to broker...")
client.connect("localhost", 1883)
client.loop_forever()




