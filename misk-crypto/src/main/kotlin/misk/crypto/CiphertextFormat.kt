package misk.crypto

import com.google.common.annotations.VisibleForTesting
import com.google.common.io.ByteStreams
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.nio.BufferOverflowException
import java.nio.ByteBuffer
import java.security.GeneralSecurityException

/**
 * Wraps a ciphertext and the encryption context associated with it in a [ByteArray].
 *
 * Misk uses Tink to encrypt data, which uses Encryption Context (EC),
 * or Additional Authentication Data (AAD) to authenticate ciphertext.
 * This class introduces a new, higher level abstraction, that’ll be used instead of the
 * AAD byte array interfaces Tink exposes to users.
 * The main reasons to do this are:
 *   - Preventing the misuse of AAD
 *   - Preventing undecipherable ciphertext from being created
 *   - Exposing a user friendlier interface
 *
 * ## Encryption Context Specification
 *   - `Map<String, String>`
 *   - The map must contain at least 1 entry
 *   - No blank or empty strings in either the map's keys or values
 *   - The map is optional, and can be completely omitted from the encryption operation
 * The encryption context will be serialized using the following format:
 * ```
 * [ AAD:
 * [ varint: pair count ]
 *   [ pairs:
 *     ( [ varint: key length ] [ ByteArray: key ]
 *       [ varint: value length ] [ ByteArray: value ]
 *     )*
 *   ]
 * ]
 * ```
 *
 * The final ouput will be serialized using the following format:
 * ```
 * [ 0xEE: magic+version ]
 * [ varint: AAD length ]
 * [ AAD ]
 * [ tink ciphertext ]
 * ```
 *
 * For the full documentation of the [EncryptionPacket] serialization, read FORMAT.md
 */
class CiphertextFormat private constructor() {

  companion object {
    /**
     * Current version of the encryption packet schema
     */
    const val CURRENT_VERSION = 0xEE

    /**
     * Serializes the given [ciphertext] and associated encryption context to a [ByteArray]
     */
    fun serialize(ciphertext: ByteArray, aad: ByteArray?): ByteArray {
      val outputStream = ByteStreams.newDataOutput()
      outputStream.writeByte(CURRENT_VERSION)
      if (aad == null) {
        outputStream.write(byteArrayOf(0))
      } else {
        outputStream.write(encodeVarInt(aad.size))
        outputStream.write(aad)
      }
      outputStream.write(ciphertext)
      return outputStream.toByteArray()
    }

    /**
     * Extract the ciphertext and associated authentication data from the [serialized] ByteArray.
     *
     * This method also compares the given [context] to the serialized AAD
     * and will throw an exception if they do not match.
     */
    fun deserialize(serialized: ByteArray, context: Map<String, String>?): Pair<ByteArray, ByteArray?> {
      val src = DataInputStream(ByteArrayInputStream(serialized))
      val version = src.readByte()
      if (version != CURRENT_VERSION.toByte()) {
        throw InvalidEncryptionPacketFormatException("invalid version: $version")
      }
      val aad: ByteArray?
      val ecSize = decodeVarInt(src)
      if (ecSize > 0) {
        aad = ByteArray(ecSize)
        src.readFully(aad)
      } else {
        aad = null
      }

      val serializedEncryptionContext = serializeEncryptionContext(context)
      if ((aad == null && serializedEncryptionContext != null) ||
          (aad != null && serializedEncryptionContext == null)) {
        throw InvalidEncryptionContextException("encryption context doesn't match")
      }
      if (aad != null) {
        val equals = serializedEncryptionContext?.contentEquals(aad)
            ?: throw InvalidEncryptionContextException("encryption context doesn't match")
        if (!equals) {
          throw InvalidEncryptionContextException("encryption context doesn't match")
        }
      }
      val ciphertext = readCiphertext(src)
      return Pair(ciphertext, aad)
    }

    /**
     * Serializes the encryption context to a [ByteArray] so it could be passed to Tink's
     * encryption/decryption methods.
     */
    fun serializeEncryptionContext(context: Map<String, String>?): ByteArray? {
      if (context == null || context.isEmpty()) {
        return null
      }

      val regex = Regex("[-_\\s]")
      val filteredKeySet = context.keys.map {
        it.toLowerCase().replace(regex, "")
      }.toSet()
      if (context.keys.size > filteredKeySet.size) {
        throw InvalidEncryptionContextException("duplicate encryption context keys")
      }
      val buffer = ByteBuffer.allocate(Short.MAX_VALUE.toInt())
      try {
        buffer.put(encodeVarInt(context.size))
        context.toSortedMap().forEach { (k, v) ->
          if (k.isEmpty() || v.isEmpty()) {
            throw InvalidEncryptionContextException("empty key or value")
          }
          val key = k.toByteArray(Charsets.UTF_8)
          val value = v.toByteArray(Charsets.UTF_8)
          if (key.size >= Short.MAX_VALUE) {
            throw InvalidEncryptionContextException("key is too long")
          }
          if (value.size >= Short.MAX_VALUE) {
            throw InvalidEncryptionContextException("value is too long")
          }
          buffer.put(encodeVarInt(key.size))
          buffer.put(key)
          buffer.put(encodeVarInt(value.size))
          buffer.put(value)
        }
      } catch (e: BufferOverflowException) {
        throw InvalidEncryptionContextException("encryption context is too long", e)
      }
      val aad = ByteArray(buffer.position())
      buffer.flip().get(aad)
      return aad
    }

    @VisibleForTesting
    fun deseriailzeEncryptionContext(aad: ByteArray?): Map<String, String>? {
      if (aad == null) {
        return null
      }
      val src = DataInputStream(ByteArrayInputStream(aad))
      var entries = decodeVarInt(src)
      if (entries == 0) {
        return null
      }
      val context = mutableMapOf<String, String>()
      while(entries > 0) {
        val keySize = decodeVarInt(src)
        val keyBytes = ByteArray(keySize)
        src.readFully(keyBytes)
        val valueSize = decodeVarInt(src)
        val valueBytes = ByteArray(valueSize)
        src.readFully(valueBytes)
        context[keyBytes.toString(Charsets.UTF_8)] = valueBytes.toString(Charsets.UTF_8)
        entries--
      }

      return context
    }

    private fun readCiphertext(src: DataInputStream) : ByteArray {
      val ciphertextStream = ByteArrayOutputStream()
      var readByte = src.read()
      while(readByte >= 0) {
        ciphertextStream.write(readByte)
        readByte = src.read()
      }
      return ciphertextStream.toByteArray()
    }

    private const val SEPTET = (1 shl 7) -1
    private const val HAS_MORE_BIT = 1 shl 7

    private fun encodeVarInt(integer: Int): ByteArray {
      val list = mutableListOf<Byte>()
      var int = integer
      var byte = int and SEPTET
      while(int shr 7 > 0) {
        list.add((byte or HAS_MORE_BIT).toByte())
        int = int shr 7
        byte = int and SEPTET
      }
      list.add(int.toByte())

      return list.toByteArray()
    }

    private fun decodeVarInt(src: DataInputStream): Int {
      var byte = src.readByte().toInt()
      var integer = byte and SEPTET
      while (byte and HAS_MORE_BIT > 0) {
        byte = src.readByte().toInt()
        integer += ((byte and SEPTET) shl 7)
      }
      return integer
    }

    /**
     * Extract the ciphertext and encryption context from the [serialized] ByteArray.
     */
    fun deserializeFleFormat(serialized: ByteArray): Pair<ByteArray, Map<String, String?>> {
      val src = DataInputStream(ByteArrayInputStream(serialized))
      val version = src.readByte().toInt()
      if (version != 1) {
        throw InvalidEncryptionPacketFormatException("")
      }
      val bitmask = src.readInt()
      if (bitmask > Short.MAX_VALUE) {
        throw InvalidEncryptionPacketFormatException("invalid bitmask")
      }
      var context = mutableMapOf<String, String?>()
      var ciphertext : ByteArray? = null
      if (bitmask != 0) {
        try {
          context.putAll(ContextKey.values()
              .filter { it.index and bitmask != 0 }
              .map { it.name.toLowerCase() to null }
              .toMap())
        } catch(e: Throwable) {
          throw InvalidEncryptionContextException("invalid bitmask", e)
        }
      }

      when(src.read()) {
        EntryType.EXPANDED_CONTEXT_DESCRIPTION.type -> {
          val size = src.readUnsignedShort()
          val serializedExpandedContextDescription = ByteArray(size)
          src.readFully(serializedExpandedContextDescription)
          val expanded = deserializeEncryptionContext(
              serializedExpandedContextDescription.toString(Charsets.UTF_8))
          context.putAll(expanded!!)
        }
        EntryType.ENCRYPTION_CONTEXT.type -> {
          val size = src.readUnsignedShort()
          val serializedContext = ByteArray(size)
          src.readFully(serializedContext)
          context = deserializeEncryptionContext(
              serializedContext.toString(Charsets.UTF_8))!!.toMutableMap()
        }
        EntryType.CIPHERTEXT.type -> {
          ciphertext = readCiphertext(src)
        }
      }
      if (ciphertext == null && src.read() == EntryType.CIPHERTEXT.type) {
        ciphertext = readCiphertext(src)
      }
      if (ciphertext == null) {
        throw InvalidEncryptionPacketFormatException("no ciphertext found")
      }

      return Pair(ciphertext, context)
    }

    private fun deserializeEncryptionContext(serialized: String) : Map<String, String?>? {
      if (serialized.isEmpty()) {
        return mapOf()
      }

      return serialized.split("|")
          .map { pair ->
            val components = pair.split("=")
            components.first() to components.getOrNull(1)
          }
          .toMap()
    }
  }

  private enum class EntryType(val type: Int) {
    UNDEFINED(0),
    EXPANDED_CONTEXT_DESCRIPTION(1),
    ENCRYPTION_CONTEXT(2),
    SIZED_CIPHERTEXT(3),
    CIPHERTEXT(4)
  }

  /**
   * Some common context keys are typically taken from the environment
   * and can be compactly encoded via a bitmask; keys and their bit offsets are defined below.
   *
   * Maximum value types supported is 15.
   */
  private enum class ContextKey constructor(val index: Int) {
    UNDEFINED(1 shl 0),
    TABLE_NAME(1 shl 1),
    DATABASE_NAME(1 shl 2),
    COLUMN_NAME(1 shl 3),
    SHARD_NAME(1 shl 4),
    PRIMARY_ID(1 shl 5),
    EVENT_TOPIC(1 shl 6),
    SERVICE_NAME(1 shl 7),
    CUSTOMER_TOKEN(1 shl 8),
  }

  class InvalidEncryptionPacketFormatException : GeneralSecurityException {
    constructor(message: String) : super(message)
    constructor(message: String, t: Throwable) : super(message, t)
  }
}