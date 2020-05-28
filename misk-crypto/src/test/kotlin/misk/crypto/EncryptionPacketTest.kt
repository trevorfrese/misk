package misk.crypto

import misk.testing.MiskTest
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatCode
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.Test
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.util.Arrays

@MiskTest
class EncryptionPacketTest {

  companion object {
    private const val VERSION_INDEX = 0
    private const val BITMASK_INDEX = 1
    private const val EC_TYPE_INDEX = 5
    private const val EC_LENGTH_INDEX = 6
    private const val EC_INDEX = 10
    private val fauxCiphertext = byteArrayOf(1, 2, 3, 4, 5, 6, 7, 8, 9, 0)
  }

  @Test
  fun testBasicEncryptionContextSerialization() {
    val context = mapOf(
        "table_name" to "unimportant",
        "database_name" to "unimportant",
        "key" to "value")
    val serialized = EncryptionPacket
        .withEncryptionContext(context)
        .serializeEncryptionContext()
        ?.toString(Charsets.UTF_8)
    assertThat(serialized)
        .isNotNull()
        .isEqualTo("database_name=unimportant|key=value|table_name=unimportant")
  }

  @Test
  fun testEmptyEncryptionContext() {
    val serialized = EncryptionPacket
        .withEncryptionContext(mapOf())
        .serializeEncryptionContext()
    assertThat(serialized)
        .isNotNull()
        .isEmpty()
  }

  @Test
  fun testDuplicateKeys() {
    val context = mapOf("Key1" to "value1", "key1" to "value1")
    assertThatThrownBy { EncryptionPacket.withEncryptionContext(context) }
        .hasMessage("found duplicate encryption context key")
  }

  @Test
  fun testNullEncryptionContext() {
    assertThat(EncryptionPacket
        .withEncryptionContext(null)
        .serializeEncryptionContext())
        .isNull()
  }

  @Test
  fun testSerializeWithAdditionalContext() {
    val context = mapOf(
        "table_name" to null,
        "database_name" to null,
        "key" to "value")
    val environmentContext = mapOf(
        "table_name" to "unimportant",
        "database_name" to "unimportant")
    val serialized = EncryptionPacket
        .withEncryptionContext(context)
        .serializeEncryptionContext(environmentContext)
        ?.toString(Charsets.UTF_8)
    assertThat(serialized)
        .isNotNull()
        .isEqualTo("database_name=unimportant|key=value|table_name=unimportant")
  }

  @Test
  fun testMissingValueInAdditinalContext() {
    val context = mapOf(
        "table_name" to null,
        "database_name" to null,
        "key" to "value")
    val environmentContext = mapOf("database_name" to "unimportant")
    assertThatThrownBy { EncryptionPacket.withEncryptionContext(context)
        .serializeEncryptionContext(environmentContext)
        ?.toString(Charsets.UTF_8)
    }.hasMessage("no value provided for table_name")
  }

  @Test
  fun testExtraValueInAdditionalContext() {
    val context = mapOf(
        "database_name" to "unimportant",
        "key" to "value")
    val environmentContext = mapOf("database_name" to "unimportant")
    assertThatThrownBy { EncryptionPacket.withEncryptionContext(context)
        .serializeEncryptionContext(environmentContext)
        ?.toString(Charsets.UTF_8)
    }.hasMessage("value already set for key database_name")
  }

  @Test
  fun testEncryptionContextWithForbiddenCharacters() {
    val context = mapOf(
        "table_name" to "=unimportant",
        "database|name" to null,
        "key" to "value")
    assertThatThrownBy { EncryptionPacket.withEncryptionContext(context)
        .serializeEncryptionContext()
        ?.toString(Charsets.UTF_8)
    }.hasMessage("Bad characters ('=', '|') in context keys: table_name, database|name")
  }

  @Test
  fun testEncryptionContextWithNullValues() {
    val context = mapOf(
        "key1" to "value1",
        "key2" to null,
        "key3" to "value1")
    val serialized = EncryptionPacket
        .withEncryptionContext(context)
        .serializeEncryptionContext()
        ?.toString(Charsets.UTF_8)
    assertThat(serialized)
        .isNotNull()
        .isEqualTo("key1=value1|key2|key3=value1")
  }

  @Test
  fun testFromByteArrayWithNoContext() {
    val serialized = EncryptionPacket
        .withEncryptionContext(null)
        .serialize(fauxCiphertext)
    assertThatCode { EncryptionPacket.fromByteArray(serialized) }
        .doesNotThrowAnyException()
    assertThatCode { EncryptionPacket.fromByteArray(serialized, null) }
        .doesNotThrowAnyException()
    assertThatThrownBy { EncryptionPacket.fromByteArray(serialized, mapOf()) }
        .hasMessage("encryption context doesn't match")
    assertThatThrownBy { EncryptionPacket.fromByteArray(serialized, mapOf("key" to "value")) }
        .hasMessage("encryption context doesn't match")
  }

  @Test
  fun testFromByteArrayWithContext() {
    val context = mapOf("key" to "value")
    val serialized = EncryptionPacket
        .withEncryptionContext(context)
        .serialize(fauxCiphertext)
    assertThatCode { EncryptionPacket.fromByteArray(serialized, context) }
        .doesNotThrowAnyException()
    assertThatThrownBy { EncryptionPacket.fromByteArray(serialized, mapOf("wrong_key" to "wrong_value")) }
        .hasMessage("encryption context doesn't match")
    assertThatThrownBy { EncryptionPacket.fromByteArray(serialized, null) }
        .hasMessage("encryption context doesn't match")
  }

  @Test
  fun testFromByteArrayWithEmptyContext() {
    val context = mapOf<String, String>()
    val serialized = EncryptionPacket
        .withEncryptionContext(context)
        .serialize(fauxCiphertext)
    assertThatCode { EncryptionPacket.fromByteArray(serialized, context) }
        .doesNotThrowAnyException()
    assertThatThrownBy { EncryptionPacket.fromByteArray(serialized, null) }
        .hasMessage("encryption context doesn't match")
    assertThatThrownBy { EncryptionPacket.fromByteArray(serialized, mapOf("key" to "value")) }
        .hasMessage("encryption context doesn't match")
  }

  @Test
  fun testUnsupportedSchemaVersion() {
    val context = mapOf("key" to "value")
    val serialized = EncryptionPacket
        .withEncryptionContext(context)
        .serialize(fauxCiphertext)
    serialized[VERSION_INDEX] = 3
    assertThatThrownBy { EncryptionPacket.fromByteArray(serialized, context) }
        .hasMessage("unsupported packet version 3")
  }

  @Test
  fun testSerializedPacketIsTooLong() {
    val context = mapOf("key" to "value")
    val serialized = EncryptionPacket
        .withEncryptionContext(context)
        .serialize(fauxCiphertext)
    val tooLong = Arrays.copyOf(serialized, serialized.size + 1)
    assertThatThrownBy { EncryptionPacket.fromByteArray(tooLong, context) }
        .hasMessage("couldn't parse data as an encryption packet")
  }

  @Test
  fun testCorruptedEncryptionContext() {
    val context = mapOf("key" to "value")
    val serialized = EncryptionPacket
        .withEncryptionContext(context)
        .serialize(fauxCiphertext)
    serialized[EC_TYPE_INDEX] = 0
    assertThatThrownBy { EncryptionPacket.fromByteArray(serialized, context) }
        .hasMessage("couldn't parse data as an encryption packet")
  }

  @Test
  fun testCorruptedCiphertext() {
    val context = mapOf("key" to "value")
    val packet = EncryptionPacket
        .withEncryptionContext(context)
    val serializedEncryptionContext = packet.serializeEncryptionContext()!!
    val serialized = packet.serialize(fauxCiphertext)
    serialized[EC_INDEX + serializedEncryptionContext.size] = 0
    assertThatThrownBy { EncryptionPacket.fromByteArray(serialized, context) }
        .hasMessage("couldn't parse data as an encryption packet")
  }

  @Test
  fun testWrongEncryptionContextSize() {
    val context = mapOf("key" to "value")
    val packet = EncryptionPacket
        .withEncryptionContext(context)
    val serializedEncryptionContext = packet.serializeEncryptionContext()!!
    val serialized = packet.serialize(fauxCiphertext)
    val newSize = ByteBuffer.allocate(4)
        .putInt((serializedEncryptionContext.size - 1))
        .array()
    for (i in newSize.indices) {
      serialized[EC_LENGTH_INDEX + i] = newSize[i]
    }
    assertThatThrownBy { EncryptionPacket.fromByteArray(serialized, context) }
        .hasMessage("couldn't parse data as an encryption packet")
  }

  @Test
  fun testCiphertextTooShort() {
    val context = mapOf("key" to "value")
    val packet = EncryptionPacket
        .withEncryptionContext(context)
    val serializedEncryptionContext = packet.serializeEncryptionContext()!!
    val serialized = packet.serialize(fauxCiphertext)
    val newCiphertextLength = ByteBuffer.allocate(4)
        .putInt(fauxCiphertext.size + 1)
        .array()
    for (i in newCiphertextLength.indices) {
      serialized[EC_LENGTH_INDEX + serializedEncryptionContext.size + 1 + i] = newCiphertextLength[i]
    }
    assertThatThrownBy { EncryptionPacket.fromByteArray(serialized, context) }
        .hasMessage("couldn't parse data as an encryption packet")
  }

  @Test
  fun testFromByteArrayV1() {
    val context = mapOf("key" to "value")
    val encryptionContext = EncryptionPacket
        .withEncryptionContext(context)
        .serializeEncryptionContext()
    val output = ByteArrayOutputStream()
    output.write(1) // VERSION
    output.writeBytes(byteArrayOf(0, 0, 0, 0))  // BITMASK
    output.write(2) // ENCRYPTION_CONTEXT
    val ecLength = ByteBuffer.allocate(2)
        .putShort(encryptionContext!!.size.toShort())
        .array()
    output.writeBytes(ecLength) // EXPANDED_CONTEXT length
    output.writeBytes(encryptionContext)
    output.write(4) // CIPHERTEXT
    output.writeBytes(fauxCiphertext)

    assertThatCode { EncryptionPacket.fromByteArray(output.toByteArray(), context) }
        .doesNotThrowAnyException()
  }

  @Test
  fun testFromByteArrayV1WithBitmask() {
    val context = mapOf("key" to "value")
    val encryptionContext = EncryptionPacket
        .withEncryptionContext(context)
        .serializeEncryptionContext()
    val output = ByteArrayOutputStream()
    output.write(1) // VERSION
    val bitmask = 1 shl 1 // TABLE_NAME
    val bitmaskBytes = ByteBuffer.allocate(4)
        .putInt(bitmask)
        .array()
    output.writeBytes(bitmaskBytes)  // BITMASK
    output.write(1) // EXPANDED_CONTEXT_DESCRIPTION
    val ecLength = ByteBuffer.allocate(2)
        .putShort(encryptionContext!!.size.toShort())
        .array()
    output.writeBytes(ecLength) // EXPANDED_CONTEXT length
    output.writeBytes(encryptionContext)
    output.write(4) // CIPHERTEXT
    output.writeBytes(fauxCiphertext)

    assertThatCode { EncryptionPacket.fromByteArray(output.toByteArray(), mapOf(
        "table_name" to null,
        "key" to "value"))
    }.doesNotThrowAnyException()
  }

  @Test
  fun testFromByteArrayV1WithBitmaskAndFullContext() {
    val context = mapOf("key" to "value")
    val encryptionContext = EncryptionPacket
        .withEncryptionContext(context)
        .serializeEncryptionContext()
    val output = ByteArrayOutputStream()
    output.write(1) // VERSION
    val bitmask = 1 shl 1 // TABLE_NAME
    val bitmaskBytes = ByteBuffer.allocate(4)
        .putInt(bitmask)
        .array()
    output.writeBytes(bitmaskBytes)  // BITMASK
    output.write(2) // ENCRYPTION_CONTEXT
    val ecLength = ByteBuffer.allocate(2)
        .putShort(encryptionContext!!.size.toShort())
        .array()
    output.writeBytes(ecLength) // EXPANDED_CONTEXT length
    output.writeBytes(encryptionContext)
    output.write(4) // CIPHERTEXT
    output.writeBytes(fauxCiphertext)

    assertThatCode { EncryptionPacket.fromByteArray(output.toByteArray(), context) }
        .doesNotThrowAnyException()
  }

  @Test
  fun testFromByteArrayV1NoContext() {
    val output = ByteArrayOutputStream()
    output.write(1) // VERSION
    output.writeBytes(byteArrayOf(0, 0, 0, 0))  // BITMASK
    output.write(4) // CIPHERTEXT
    output.writeBytes(fauxCiphertext)

    assertThatCode { EncryptionPacket.fromByteArray(output.toByteArray(), mapOf()) }
        .doesNotThrowAnyException()
  }

  @Test
  fun testFromByteArrayV1EmptyContext() {
    val output = ByteArrayOutputStream()
    output.write(1) // VERSION
    output.writeBytes(byteArrayOf(0, 0, 0, 0))  // BITMASK
    output.write(2) // ENCRYPTION_CONTEXT
    output.writeBytes(byteArrayOf(0, 0))
    output.write(4) // CIPHERTEXT
    output.writeBytes(fauxCiphertext)

    assertThatCode { EncryptionPacket.fromByteArray(output.toByteArray(), mapOf()) }
        .doesNotThrowAnyException()
  }

  @Test
  fun testFromByteArrayV1BitmaskOnly() {
    val output = ByteArrayOutputStream()
    output.write(1) // VERSION
    val bitmask = 1 shl 1 // TABLE_NAME
    val bitmaskBytes = ByteBuffer.allocate(4)
        .putInt(bitmask)
        .array()
    output.writeBytes(bitmaskBytes)  // BITMASK
    output.write(4) // CIPHERTEXT
    output.writeBytes(fauxCiphertext)

    assertThatCode { EncryptionPacket.fromByteArray(output.toByteArray(), mapOf("table_name" to null)) }
        .doesNotThrowAnyException()
  }
}