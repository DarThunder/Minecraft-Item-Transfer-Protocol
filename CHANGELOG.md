# Changelog

## 0.5
### features
- Session creation.
- Message validation.
- Implementation of checksums.

## 0.6
### features
- init() method has been added
- automatic modem assignment
- support for TCP and MIPT message validation
- recipient validation Major improvements:
- required "method" header in the buildMITPMessage function
- Checksum now works with nested tables

### Fixes
- data validation logic
- session validation logic
