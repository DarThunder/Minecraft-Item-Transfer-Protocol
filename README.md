# Minecraft Item Transfer Protocol (MITP)
## 🔎 About
MITP is a protocol for item transfer within Minecraft using [ComputerCraft: Tweaked](https://github.com/cc-tweaked/CC-Tweaked). The goal is to establish an efficient connection between devices for the reliable exchange of data in Minecraft. MITP simulates the behavior of a basic TCP persistant protocol to ensure transmission reliability and security.

## ⚙️ Features
- Item Transfers: Send and receive items between devices within Minecraft.
- Session Management: Maintain reliable connections during item transfers.
- Message Validation: Ensures messages are valid with headers, checksums, and authentication.
- Secure Connections: Data encryption and authentication for secure communication.
- Ephemeral Ports: Temporary communication ports for secure, short-term connections.
- Event Handling: New event-subscription system for better flexibility in handling actions.
- Automatic Message Handling: Supports automatic handling of TCP and MITP messages.
- Asynchronous Communication: Non-blocking communication for better performance.
- Encryption: AES encryption and SHA-256 for data security.
- Logging: Built-in activity logging for auditing and debugging.

## ✅ RoadMap
### Short-Term (1-2 months)
**Goal:** Improve asynchronous communication and add HMAC.

- **Actions:**
  - Refine the asynchronous event system.
  - Implement the HMAC (Hashed Message Authentication Code) algorithm to ensure message integrity and authenticity.
  - Optimize the efficiency of the asynchronous message flow.
  - Perform stability tests with different data loads.

**Start Date:** 01/2025  
**End Date:** 02/2025

---

### Mid-Term (3-4 months)
**Goal:** Add basic, stable reconnection mechanisms.

- **Actions:**
  - Implement an automatic reconnection system in case of connection loss.
  - Add failure handling for disconnection scenarios.
  - Implement temporary data storage during reconnection.
  - Test stability under different network conditions.

**Start Date:** 02/2025  
**End Date:** 04/2025

---

### Long-Term (6+ months)
**Goal:** Support functions and files of any extension.

- **Actions:**
  - Develop a system to handle files of any type or extension.
  - Create a mechanism to invoke remote functions through the protocol.
  - Optimize the transfer of large files and remote functions.
  - Conduct extensive testing to ensure interoperability with different systems.

**Start Date:** 05/2025  
**End Date:** 10/2025

## 🧾 Changelog
You should see the changelog version in [CHANGELOG.](./CHANGELOG.md)

## 🤝 Contributing
We welcome contributions! If you'd like to contribute, please follow our [Contributing Guide](CONTRIBUTING.md) for steps on how to get involved.

## © License
This project is licensed under the GPL-3.0 License. See the [LICENSE](./LICENSE) file for more details.

## 💎 Credits
### Developers
- [DarThunder](https://github.com/DarThunder)

### Contributors
- [JoseANG3L](https://github.com/JoseANG3L)
