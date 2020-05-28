# Misk encryption packet format

# Misk encryption packet format

## Overview

Misk uses Tink to encrypt data, which uses Encryption Context (EC), 
or Additional Authentication Data (AAD) to authenticate ciphertext.

Instead of using Tink's byte array AAD, 
Misk introduces a new higher level abstraction that’ll be used instead of the encryption 
interfaces Tink exposes to users.

The main reasons to do this are:

1. Preventing the misuse of AAD
2. Preventing undecipherable ciphertext from being created
3. Exposing a user friendlier interface

## Details

The use of AAD can be confusing to users. 
In Tink, AAD is represented by an array of bytes, which is hard to deal with when debugging
and can be easily corrupted and misused.

On top of that different languages and environments may parse byte arrays in different ways.

Instead of letting misk-crypto users supply their own byte array as AAD, 
we decided to expose a more convenient data structure - a map of strings where 
each key-value pair in the map represents a context variable and its value.

When encrypting/decrypting with misk-crypto, 
the encryption context map will be serialized to a byte array and used instead.

## Encryption Context Specification

- `Map<String, String?>`
- `null` values are allowed
- No `=` or `|` characters are allowed in the encryption context
- EC is optional, and can be completely omitted from the encryption operation

The encryption context will be serialized using the following format:

```kotlin
// before serialization
val context = mapOf(
    “key1 to “value1”, 
    “key2” to null, 
    “key3 to “value3”
)

// after serialization
EncryptionPacket.serializeEncryptionContext(context)
// “key1=value1|key2|key3=value3”
```

## General Format

The serialized EC used when creating the ciphertext and the ciphertext are put together in an EncryptionPacket format.

Below is the exact specification of the encryption packet.

### V1 Schema
| Size | Description | Type |
|------|-------------|------|
| 1 | Schema version, encoded as a single byte | Integer |
| 2 | Bitmask representing the presence of common encryption context keys. This field is used to reduce the size of the complete packet. Some EC keys are very common (for example, SERVICE_NAME), and can be represented as a bit in the bitmask instead of including all `key=value` pairs | Integer |
| 1 | The number 2 - representing the following bytes are the complete serialized AAD | Integer |
| 2 | Length | Integer |
| AAD array length | Serialized AAD | ByteArray |
| 1 | The number 1 - representing the following bytes are the “expanded context description” serialized AAD | Integer |
| 2 | Length | Integer |
| Context description length | Serialized expanded context description | ByteArray |
| 1 | The number 4 - representing the following bytes are ciphertext | Integer |
| Ciphertext length | Ciphertext | ByteArray |

- First 2 fields are required
- Serialized AAD and serialized expanded context description are mutually exclusive
- Ciphertext is required
- The order of the above sections is permanent

### V2 Schema
| Size | Description | Type |
|------|-------------|------|
| 1 | Schema version, encoded as a single byte | Integer |
| 2 | Bitmask (not used)) | Integer |
| 1 | The number 2 - representing the following bytes are the complete serialized AAD | Integer |
| 2 | Length | Integer |
| AAD array length | Serialized AAD | ByteArray |
| 1 | The number 3 - representing the following bytes are ciphertext | Integer |
| 2 | Ciphertext length | Integer |
| Ciphertext length | Ciphertext | ByteArray |

- Serialized encryption context is optional
