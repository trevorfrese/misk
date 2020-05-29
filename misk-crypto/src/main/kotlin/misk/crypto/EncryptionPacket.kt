package misk.crypto

import com.google.common.io.ByteStreams
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.security.GeneralSecurityException

/**
 * An [EncryptionPacket] wraps a ciphertext and the encryption context associated with it.
 *
 * Misk uses Tink to encrypt data, which uses Encryption Context (EC),
 * or Additional Authentication Data (AAD) to authenticate ciphertext.
 * This class introduces a new, higher level abstraction, that’ll be used instead of the
 * AAD byte array interfaces Tink exposes to users.
 * The main reasons to do this are:
 *   - Preventing the misuse of AAD
 *   - Preventing undecipherable ciphertexts from being created
 *   - Exposing a user friendlier interface
 *
 * ## Encryption Context Specification
 *   - `Map<String, String?>`
 *   - Null values are allowed
 *   - No "=" or "|" characters are allowed in the encryption context
 *   - EC is optional, and can be completely omitted from the encryption operation
 * The encryption context will be serialized using the following format:
 * `key1=value1|key2|key3=value3`
 *
 * For the full documentation of the [EncryptionPacket] serialization, read FORMAT.md
 */
class EncryptionPacket private constructor(
  private val context: Map<String, String?>?,
  var ciphertext: ByteArray?
) {

  companion object {
    /**
     * Current version of the encryption packet schema
     */
    const val CURRENT_VERSION = 2

    /**
     * Creates a new [EncryptionPacket] with the given encryption context map
     */
    fun withEncryptionContext(context: Map<String, String?>?) : EncryptionPacket {
      if (context == null) {
        return EncryptionPacket(null, null)
      }
      val sanitizedContext = context.map { (k, v) -> k.toLowerCase() to v }.toMap()
      if ((context.keys - sanitizedContext.keys).isNotEmpty()) {
        throw InvalidEncryptionContextException("found duplicate encryption context key")
      }
      return EncryptionPacket(sanitizedContext, null)
    }

    /**
     * Creates a new [EncryptionPacket] from the given [serialized] ByteArray.
     */
    fun fromByteArray(
      serialized: ByteArray,
      encryptionContext: Map<String, String?>? = null
    ) : EncryptionPacket {
      val src = DataInputStream(ByteArrayInputStream(serialized))

      val packet = when(val version = src.readUnsignedByte()) {
        1 ->
          parseV1(src)
        CURRENT_VERSION ->
          parseV2(src)
        else ->
          throw InvalidEncryptionPacketFormatException(
              String.format("unsupported packet version %s", version))
      }
      if (packet.context != null) {
        if (encryptionContext == null) {
          throw InvalidEncryptionContextException("encryption context doesn't match")
        }
        val compareTo = withEncryptionContext(encryptionContext).serializeEncryptionContext()!!
        if (!packet.serializeEncryptionContext()!!.contentEquals(compareTo)) {
          throw InvalidEncryptionContextException("encryption context doesn't match")
        }
      } else if (encryptionContext != null) {
        throw InvalidEncryptionContextException("encryption context doesn't match")
      }
      return packet
    }

    private fun parseV2(src :DataInputStream) : EncryptionPacket {
      // (bitmask) not used
      src.readInt()

      val ciphertext: ByteArray?
      var context: Map<String, String?>? = null
      var type = src.read()
      if (type == EntryType.ENCRYPTION_CONTEXT.type) {
        var size = src.readInt()
        val serializedContext = ByteArray(size)
        src.readFully(serializedContext)
        context = deserializeEncryptionContext(serializedContext.toString(Charsets.UTF_8))
        type = src.read()
        if (type != EntryType.SIZED_CIPHERTEXT.type) {
          throw InvalidEncryptionContextException("couldn't parse data as an encryption packet")
        }
        size = src.readInt()
        ciphertext = ByteArray(size)
        src.readFully(ciphertext)
      } else if (type == EntryType.SIZED_CIPHERTEXT.type) {
        val size = src.readInt()
        ciphertext = ByteArray(size)
        src.readFully(ciphertext)
      } else {
        throw InvalidEncryptionContextException("couldn't parse data as an encryption packet")
      }

      if (src.read() >= 0) {
        throw InvalidEncryptionContextException("couldn't parse data as an encryption packet")
      }

      return EncryptionPacket(context, ciphertext)
    }

    private fun parseV1(src : DataInputStream) : EncryptionPacket {
      val bitmask = src.readInt()
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
        throw InvalidEncryptionPacketFormatException("no ciphetext found")
      }

      return EncryptionPacket(context, ciphertext)
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

    private fun deserializeEncryptionContext(serialized: String?) : Map<String, String?>? {
      if (serialized == null) {
        return null
      }
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

  /**
   * Serializes the encryption context to a [ByteArray] s it could be passed to Tink's
   * encryption/decryption methods.
   */
  fun serializeEncryptionContext(additionalContext: Map<String, String>? = null) : ByteArray? {
    if (context == null) {
      return null
    }
    val toSerialize: Map<String, String?>?
    if (additionalContext != null) {
      toSerialize = context.mapValues { (k, v) ->
        if (v == null) {
          additionalContext.getOrElse(k) {
            throw InvalidEncryptionContextException("no value provided for $k")
          }
        } else {
          if (additionalContext.containsKey(k)) {
            throw InvalidEncryptionContextException("value already set for key $k")
          }
          v
        }
      }
    } else {
      toSerialize = context
    }
    val filtered = toSerialize.mapNotNull { (key, v) ->
      if ((key + v.orEmpty()).indexOfAny(charArrayOf('=', '|')) >= 0) key else null
    }
    if (filtered.isNotEmpty()) {
      val where = if (filtered.size > 1) "keys" else "key"
      throw InvalidEncryptionContextException(
          "Bad characters ('=', '|') in context $where: ${filtered.joinToString(", ")}")
    }

    return toSerialize.asSequence()
        .sortedBy { (k, v) -> k.toLowerCase() + (v?.toLowerCase() ?: "") }
        .map { (key, value) -> if (value == null) key else "$key=$value" }
        .joinToString("|")
        .toByteArray()
  }

  /**
   * Serializes the given [ciphertext] and associated encryption context to a [ByteArray]
   */
  fun serialize(ciphertext: ByteArray) : ByteArray {
    val outputStream = ByteStreams.newDataOutput()
    outputStream.writeByte(CURRENT_VERSION)
    outputStream.writeInt(0)
    if (context != null) {
      val serializedContext = serializeEncryptionContext()!!
      outputStream.writeByte(EntryType.ENCRYPTION_CONTEXT.type)
      outputStream.writeInt(serializedContext.size)
      outputStream.write(serializedContext)
    }
    outputStream.writeByte(EntryType.SIZED_CIPHERTEXT.type)
    outputStream.writeInt(ciphertext.size)
    outputStream.write(ciphertext)
    return outputStream.toByteArray()
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