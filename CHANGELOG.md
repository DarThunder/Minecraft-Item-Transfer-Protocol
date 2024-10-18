# Changelog

## 0.5
### Features
- Session creation.
- Message validation.
- Implementation of checksums.

## 0.6
### Features
- init() method has been added
- Automatic modem assignment
- Support for TCP and MIPT message validation
- Recipient validation Major improvements:
- Required "method" header in the buildMITPMessage function
- Checksum now works with nested tables

### Fixes
- Data validation logic
- Session validation logic
