package misk.crypto

import misk.testing.MiskTest
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatCode
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.Test
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
    val packet = EncryptionPacket.withEncryptionContext(context)
    val serialized = packet.serializeEncryptionContext()?.toString(Charsets.UTF_8)
    assertThat(serialized)
        .isNotNull()
        .isEqualTo("database_name=unimportant|key=value|table_name=unimportant")
  }

  @Test
  fun testDuplicateKeys() {
    val context = mapOf("Key1" to "value1", "key1" to "value1")
    assertThatThrownBy { EncryptionPacket.withEncryptionContext(context) }
        .hasMessage("found duplicate encryption context key")
  }

  @Test
  fun testNullEncryptionCntext() {
    val packet = EncryptionPacket.withEncryptionContext(null)
    assertThat(packet.serializeEncryptionContext()).isNull()
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
    val packet = EncryptionPacket.withEncryptionContext(context)
    val serialized = packet.serializeEncryptionContext(environmentContext)?.toString(Charsets.UTF_8)
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
    val packet = EncryptionPacket.withEncryptionContext(context)
    assertThatThrownBy {
      packet.serializeEncryptionContext(environmentContext)?.toString(Charsets.UTF_8)
    }.hasMessage("no value provided for table_name")
  }

  @Test
  fun testExtraValueInAdditionalContext() {
    val context = mapOf(
        "database_name" to "unimportant",
        "key" to "value")
    val environmentContext = mapOf("database_name" to "unimportant")
    val packet = EncryptionPacket.withEncryptionContext(context)
    assertThatThrownBy {
      packet.serializeEncryptionContext(environmentContext)?.toString(Charsets.UTF_8)
    }.hasMessage("value already set for key database_name")
  }

  @Test
  fun testEncryptionContextWithForbiddenCharacters() {
    val context = mapOf(
        "table_name" to "=unimportant",
        "database|name" to null,
        "key" to "value")
    val packet = EncryptionPacket.withEncryptionContext(context)
    assertThatThrownBy {
      packet.serializeEncryptionContext()?.toString(Charsets.UTF_8)
    }.hasMessage("Bad characters ('=', '|') in context keys: table_name, database|name")
  }

  @Test
  fun testEncryptionContextWithNullValues() {
    val context = mapOf(
        "key1" to "value1",
        "key2" to null,
        "key3" to "value1")
    val packet = EncryptionPacket.withEncryptionContext(context)
    val serialized = packet.serializeEncryptionContext()?.toString(Charsets.UTF_8)
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
}