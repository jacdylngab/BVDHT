# BVDHT: A Lightweight Distributed Hash Table

`BVDHT` is a Python-based distributed hash table (DHT) implementation designed to support dynamic peer membership, key-value storage, and basic peer-to-peer communication using a custom socket protocol. This project demonstrates key distributed systems concepts including consistent hashing and peer discovery.

---

## 🧠 Features

### ✅ Hash Table Operations

- Insert: Adds or updates a key-value pair.

- Get: Retrieves a value by key.

- Remove: Deletes a key (no-op if not found).

- Contains: Checks for existence of a key.


### ✅ DHT Protocols

- Locate: Determines the peer responsible for a given hash key.

- Connect: Joins a new peer into the DHT.

- Disconnect: Gracefully exits the DHT and transfers key ownership.

- UpdatePrev: Updates the prev reference on neighboring nodes.

## 🚀 How to Run

### 1. Clone the Repository
```
git clone https://github.com/jacdylngab/BVDHT.git
```

### 2. Navigate into the Project Directory
```
cd BVDHT
```

### 3. Run the Program
🌀 Starting a New DHT Ring
To start a brand-new DHT (i.e., the first peer):
```
python3 bvDHT.py
```
This initializes a fresh DHT network with the current peer as the only member.

🔗 Joining an Existing DHT
To join an existing DHT network, provide the IP address and port number of an active peer:
```
python3 bvDHT.py <peer_ip_address> <peer_port>
```
Example:
```
python3 bvDHT.py 127.0.0.1 5000
```
