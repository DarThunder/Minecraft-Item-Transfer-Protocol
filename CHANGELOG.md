## 0.5
### Features
- Added session creation.
- Added message validation.
- Implemented checksums.

## 0.6
### Features
- Added `init()` method.
- Automatic modem assignment.
- Support for TCP and MITP message validation.
- Major improvements to recipient validation.
- Required `"method"` header in the `buildMITPMessage` function.
- Checksum now supports nested tables.

### Fixes
- Improved data validation logic.
- Enhanced session validation logic.

## 0.7
### Features 
- Added `recv()` method.
- Added `autoRecv()` method.
- Added `handlerRequest()` method.
- Added `shieker()` method.
- Added `on()` method.
- Added `open()` method.
- Added `openResponse()` method.
- Added `parseMessageBody()` method.
- Implemented automatic handling of TCP messages.
- Introduced a new event-subscription system for greater flexibility.
- Changed scope for multiple functions and variables.
- Added support for asynchronous communication.
- Added MITP message handler.

### Fixes
- Minor updates to global variable names.
- Improved logic for message validation.
- Renamed functions:
    - `sendClose()` to `close()`
    - `handleClose()` to `closeResponse()`
- Refactored `close()` and `closeResponse()` functions.
- Added event filter support for the `listenConnection()` function.
- Minor updates to `createSession()` and `destroySession()` functions.
- Removed the `connectionTimeOut()` method.

## 0.8
### Features
- Added library `encryptLib`.
    - Added method `encryptAES()`.
    - Added method `decryptAES()`.
    - Added method `sha256()`.
    - Added method `generateSalt()`.
    - Added method `generateSecrets()`.
    - Added method `modExp()`.
- Added library `validatorLib`.
    - Added method `validateInput()`.
- Added method `depose()`
- Added method `sendRECV()`.
- Added method `sendNRECV()`.
- Added method `sendErrorResponse()`.
- Added new variable `lastAction`.
- Added new variable `secrets`.

### Changes
- Moved all validation logic to the `validatorLib` library.
- Modified the logic of the `await()` method.
- TCP and MITP messages now use SHA-256 signatures instead of a simple checksum.
- The Diffie-Hellman algorithm has been incorporated into the initial TCP handshake.
- The `buildMITPMessage()` function has been renamed to `buildMessage()`.
- The handling of TCP and MITP messages now works correctly for both client and server.
- Now, every correctly validated message will send a RECV flag, and in case of a validation failure, an NRECV flag will be sent.
- A mechanism to resend the last message in case of transmission malformation has been added.

### Known Issues
- We are currently investigating an issue where `shared_key` may not save correctly at the end of the TCP handshake, resulting in a nil value. We plan to resolve this issue in the next version.
- The `millerRabin()` algorithm occasionally takes longer than expected to verify if a number is prime, regardless of bit size. We are investigating the cause of this behavior and considering optimizing or completely replacing the algorithm.

### Fixes
- Minor fixes to improve the robustness of message validation and handling.
