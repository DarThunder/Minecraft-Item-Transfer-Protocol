# Minecraft Item Transfer Protocol (MITP)
## 🔎 Overview
Minecraft Item Transfer Protocol (MITP) is a high-performance communication protocol designed to handle item data transfers and general communication in Minecraft, optimized for both asynchronous communication and secure data transmission. This protocol implements advanced cryptographic techniques (AES-128, SHA-256, HMAC) and supports compression via Huffman coding, ensuring efficient and secure data exchanges.

## ⚙️ Features
- AES-128 Encryption: Uses Rijndael encryption for secure data transmission.
- SHA-256 Hashing: Ensures message integrity with SHA-256 signatures.
- HMAC: Provides additional message authentication.
- Compression: Implements Huffman coding for data compression.
- TCP-like Communication: Emulates a reliable TCP connection for sending and receiving data.
- Asynchronous Communication: Supports non-blocking communication to improve performance.
- Event-driven Architecture: Flexible event handling system to manage different communication events.

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
