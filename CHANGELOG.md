# Changelog

## 0.5
### Features
- Session creation.
- Message validation.
- Implementation of checksums.

## 0.6
### Features
- `init()` method has been added.
- Automatic modem assignment.
- Support for TCP and MIPT message validation.
- Recipient validation Major improvements.
- Required "method" header in the buildMITPMessage function.
- Checksum now works with nested tables.

### Fixes
- Data validation logic.
- Session validation logic.

## 0.7
### Features 
- `recv()` method has been added.
- `autoRecv()` method has been added.
- `handlerRequest()` method has been added.
- `shieker()` method has been added.
- `on()` method has been added.
- `open()` method has been added.
- `openResponse()` method has been added.
- `parseMessageBody()` method has been added.
- Automatic handling of TCP messages.
- New event-subscription system for greater flexibility.
- Scope change for multiple functions and variables.
- Support for asynchronous communication.
- Added MITP message handler.

### Fixes
- Minor changes to global variable names.
- Improved logic for message validation.
- Renamed functions:
    - sendClose -> close.
    - handleClose -> closeResponse.
- Refactoring for close and closeResponse functions.
- Event filter support for listenConnection function.
- Minor changes to createSession and destroySession functions.
- Removed connectionTimeOut method.
