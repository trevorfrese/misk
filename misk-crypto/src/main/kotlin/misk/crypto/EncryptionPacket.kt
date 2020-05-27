package misk.crypto

import com.google.common.io.ByteStreams
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream

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
        throw InvalidEncryptionContextException("")
      }
      return EncryptionPacket(sanitizedContext, null)
    }

    /**
     * Creates a new [EncryptionPacket] from the given [serialized] ByteArray.
     *
     * Thiis function parses the [serialized]
     */
    fun fromByteArray(serialized: ByteArray, encryptionContext: Map<String, String?>? = null): EncryptionPacket {
      val src = DataInputStream(ByteArrayInputStream(serialized))

      val packet = when(val version = src.readUnsignedByte()) {
        1 ->
          parseV1(src)
        CURRENT_VERSION ->
          parseV2(src)
        else ->
          throw InvalidEncryptionContextException(
              String.format("unsupported packet version %s", version))
      }
      if (packet.context != null) {
        if (encryptionContext == null) {
          throw InvalidEncryptionContextException("")
        }
        val compareTo = EncryptionPacket
            .withEncryptionContext(encryptionContext).serializeEncryptionContext()!!
        if (!packet.serializeEncryptionContext()!!.contentEquals(compareTo)) {
          throw InvalidEncryptionContextException("")
        }
      } else if (encryptionContext != null) {
        throw InvalidEncryptionContextException("")
      }
      return packet
    }

    private fun parseV2(src :DataInputStream) : EncryptionPacket {
      // (bitmask) not used
      src.readInt()

      var ciphertext: ByteArray? = null
      var context: Map<String, String?>? = null
      val type = src.read()
      if (type == EntryType.ENCRYPTION_CONTEXT.type) {
        val size = src.readInt()
        val serializedContext = ByteArray(size)
        src.readFully(serializedContext)
        context = deserializeEncryptionContext(serializedContext.toString(Charsets.UTF_8))
      }
      if (type == EntryType.SIZED_CIPHERTEXT.type) {
        val size = src.readInt()
        ciphertext = ByteArray(size)
        src.readFully(ciphertext)
      }

      if (src.read() >= 0) {
        throw InvalidEncryptionContextException("")
      }
      if (ciphertext == null) {
        throw InvalidEncryptionContextException("")
      }

      return EncryptionPacket(context, ciphertext)
    }

    private fun parseV1(src : DataInputStream) : EncryptionPacket {
      val bitmask = src.readUnsignedShort()
      var context : MutableMap<String, String?>? = null
      if (bitmask != 0) {
        context = mutableMapOf()
        try {
          context.putAll(ContextKey.values()
              .filter { it.index and bitmask != 0 }
              .map { it.name.toLowerCase() to null }
              .toMap())
        } catch(e: Throwable) {
          throw InvalidEncryptionContextException("", e)
        }
      }

      if (context != null) {
        if (src.read() != EntryType.EXPANDED_CONTEXT_DESCRIPTION.type) {
          throw InvalidEncryptionContextException("")
        }
        val size = src.readUnsignedShort()
        val serializedExpandedContextDescription = ByteArray(size)
        src.readFully(serializedExpandedContextDescription)
        val expanded = deserializeEncryptionContext(
            serializedExpandedContextDescription.toString(Charsets.UTF_8))
        context.putAll(expanded!!)
      } else {
        if (src.read() != EntryType.ENCRYPTION_CONTEXT.type) {
          throw InvalidEncryptionContextException("")
        }
        val size = src.readUnsignedShort()
        val serializedContext = ByteArray(size)
        src.readFully(serializedContext)
        context = deserializeEncryptionContext(
            serializedContext.toString(Charsets.UTF_8))!!.toMutableMap()
      }
      if (src.read() != EntryType.CIPHERTEXT.type) {
        throw InvalidEncryptionContextException("")
      }
      val ciphertextStream = ByteArrayOutputStream()
      var readByte = src.read()
      while(readByte >= 0) {
        ciphertextStream.write(readByte)
        readByte = src.read()
      }
      val ciphertext = ciphertextStream.toByteArray()
      return EncryptionPacket(context, ciphertext)
    }

    private fun deserializeEncryptionContext(serialized: String?) : Map<String, String?>? {
      if (serialized == null) {
        return null
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
   *
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
            throw InvalidEncryptionContextException("")
          }
        } else {
          if (additionalContext.containsKey(k)) {
            throw InvalidEncryptionContextException("")
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
   *
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
   * Some common context keys are typically taken from the environment and can be compactly encoded via a bitmask; keys
   * and their bit offsets are defined below.
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
}