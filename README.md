# yjs-ws-message-reader

```
[0]     0x00          - Message type (0 = sync/update)
[1]     0x02          - Number of structs in this update = 2
[2]     0x18 = 24     - Content/info byte (likely struct flags or content type)

[3]     varint 1      - ?
[4]     varint 1      - ?
[5-9]   varint 454648744  - CLIENT ID (your peer/session identifier)
[10-11] varint 4077 / 4082  - CLOCK A  ← increments by 5 between messages
[12-17] varint (contains client ID again)
[18-19] varint 4076 / 4081  - CLOCK B  ← also increments by 5 (always clock A - 1)
[20]    0x05          - string length prefix = 5 (length of "hello")
[21-25] "hello"       - your plaintext content
[26]    0x00          - null / content type marker

[27-37] identical in both - document state vector or HMAC tail
```
