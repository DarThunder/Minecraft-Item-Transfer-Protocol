# Minecraft Item Transfer Protocol (MITP) Documentation
## Overview
Minecraft Item Transfer Protocol (MITP) is a high-performance, secure communication protocol designed for ComputerCraft: Tweaked, facilitating item data transfers and general communication. It supports AES-128 encryption, SHA-256 hashing, HMAC authentication (No really WIP), and data compression using Huffman coding. MITP also includes asynchronous communication, similar to a TCP-like protocol, and an event-driven architecture for flexibility.

This documentation is aimed at developers looking to understand the protocol’s architecture, how to interact with it, and how to integrate it into their Minecraft mods or applications.

## Download
To install the protocol and all its dependencies, simply paste the following command into a computer terminal:
```bash
wget run https://raw.githubusercontent.com/DarThunder/Minecraft-Item-Transfer-Protocol/refs/heads/main/installer.lua
```
You will see the installation progress, and once it's finished, you can start using it without any issues.

## Architecture
MITP is designed with modularity and performance in mind. The protocol is divided into multiple components:

1. Core Protocol: Handles the main communication logic, including message creation, encryption, and data transfer.
2. Encryption: Uses AES-128 (Rijndael) for encryption and decryption, and SHA-256 for message integrity.
3. Compression: Implements Huffman coding to compress data before sending it, improving performance.
4. Network: Emulates a TCP-like communication model, supporting both client and server interactions.
5. Variables: A flexible event system that allows users to define custom events and handle them asynchronously.

## Components

### 1. MITP
The core of the protocol. It instantiates the two main actors: the client and the server. It also handles all events.

#### Example
```lua
local MITP = require("MITP")
local client = MITP.Client.new(1, 80)
local server = MITP.Server.new(80)
```

### 2. Client
The client is one of the main actors. It initializes the connection with the server, sending and receiving messages.

#### Methods
 - `2.1 Client:transmit()`
Allows the client to send messages to the server.

- Parameters:
    - payload: The message to send (can be any primitive data type, including tables).
    - flag?: (Optional) The type of flag to use.
- Returns:
    - true if the operation was successful.
    - false if something went wrong during transmission.

#### Example:
```lua
local success = client:transmit("Hello Server", "INFO")
if not success then
    print("Error transmitting the message.")
end
```

- `2.2 Client:recv()`
Allows the client to receive messages from the server.

- Parameters: None.

- Returns:
    - A table of type packet if the message was successfully received.
    - nil in case of an error.

#### Example:
```lua
local message = client:recv()
if message then
    print("Message received:", message.data.data)
else
    print("No message received.")
end
```

### 3. Server
The server is the other main actor, which is responsible for gathering information.

#### Methods
- `3.1 Server:on()`
Associates an action with a specified flag.

- Parameters:
    - flag: The flag to which the action will be applied.
    - action: The function that defines the action.

Example:
```lua
server:on("INFO", function(conn, packet)
    print("Received:", packet.data.data)
    conn:send("Response from the server")
end)
```

- `3.2 Server:autoRecv()`
Handles incoming requests. It is typically added at the end of the program.

- Parameters: None.

- Returns: None.

Example:
```lua
server:autoRecv()
```

### 4. Connection
Although there are only two main actors, the Server has the characteristic that the function used in the on method has another sub-actor called "connection," which is the socket that will be used to communicate with a specific client.

#### Methods
- `4.1 Conn:send()`
Allows sending messages to a specific client.

- Parameters:
    - payload: The message to send (can be any primitive data type, including tables).

- Returns:
    - true if the operation was successful.
    - false if something went wrong during the message sending.

Example:
```lua
local success = conn:send("Hello client!")
if not success then
  print("Error sending the message.")
end
```
