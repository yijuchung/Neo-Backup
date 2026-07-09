package com.machiav3lli.backup.utils

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.nio.charset.StandardCharsets
import javax.crypto.SecretKey

/**
 * Local-JVM unit tests for [CryptoUtils].
 *
 * These cover password-based key derivation ([generateKeyFromPassword]), salt/nonce
 * generation ([generateSalt] / [initIv]) and the full AES/GCM encrypt/decrypt round-trip.
 *
 * The round-trip runs on the desktop SunJCE provider because the cipher now uses
 * [javax.crypto.spec.GCMParameterSpec] (SunJCE-compatible), unlike the previous
 * `IvParameterSpec`-based code that only worked under Android's Conscrypt. The on-device
 * behavior with Conscrypt is additionally exercised by an instrumented test.
 */
class CryptoUtilsTest {

    private val plain = "secret backup payload — 1234567890".toByteArray(Charsets.UTF_8)

    private fun salt(s: String) = s.toByteArray(StandardCharsets.UTF_8)

    // Derive with a low iteration count to keep the round-trip tests fast; the KDF cost
    // itself is asserted separately below.
    private fun testKey(password: String = "pw"): SecretKey =
        generateKeyFromPassword(password, salt("saltvalue"), iterationCount = 1_000)

    private fun encrypt(key: SecretKey, data: ByteArray): ByteArray {
        val bos = ByteArrayOutputStream()
        bos.encryptStream(key).use { it.write(data) }
        return bos.toByteArray()
    }

    private fun decrypt(key: SecretKey, cipherText: ByteArray): ByteArray =
        ByteArrayInputStream(cipherText).decryptStream(key).use { it.readBytes() }

    // --- key derivation -----------------------------------------------------------------

    @Test
    fun derivedKey_hasExpected256BitAesKey() {
        val key = generateKeyFromPassword("correct horse", salt("saltvalue"))
        assertEquals("AES", key.algorithm)
        assertEquals(32, key.encoded.size) // 256-bit key
    }

    @Test
    fun derivedKey_isDeterministicForSameInputs() {
        val a = generateKeyFromPassword("pw", salt("saltvalue")).encoded
        val b = generateKeyFromPassword("pw", salt("saltvalue")).encoded
        assertTrue(a.contentEquals(b))
    }

    @Test
    fun derivedKey_dependsOnSalt() {
        // Rationale: a constant/shared salt lets keys be precomputed across users/backups.
        // Different salts must yield different keys.
        val a = generateKeyFromPassword("pw", salt("salt-A")).encoded
        val b = generateKeyFromPassword("pw", salt("salt-B")).encoded
        assertFalse(a.contentEquals(b))
    }

    @Test
    fun derivedKey_dependsOnPassword() {
        val a = generateKeyFromPassword("password-A", salt("saltvalue")).encoded
        val b = generateKeyFromPassword("password-B", salt("saltvalue")).encoded
        assertFalse(a.contentEquals(b))
    }

    @Test
    fun derivedKey_dependsOnIterationCount() {
        // The per-backup iteration count must actually change the derived key, otherwise
        // recording it in metadata would be meaningless.
        val a = generateKeyFromPassword("pw", salt("saltvalue"), iterationCount = 1_000).encoded
        val b = generateKeyFromPassword("pw", salt("saltvalue"), iterationCount = 2_000).encoded
        assertFalse(a.contentEquals(b))
    }

    @Test
    fun derivedKey_honorsKeyLength() {
        val k128 = generateKeyFromPassword("pw", salt("saltvalue"), keyLength = 128)
        val k256 = generateKeyFromPassword("pw", salt("saltvalue"), keyLength = 256)
        assertEquals(16, k128.encoded.size)
        assertEquals(32, k256.encoded.size)
    }

    @Test
    fun defaultIterationCount_meetsOwasp2023() {
        // Guards against a regression back to the old, far-too-low work factor (2020).
        assertEquals(600_000, ITERATION_COUNT)
    }

    // --- salt / nonce generation --------------------------------------------------------

    @Test
    fun generateSalt_hasExpectedLength() {
        assertEquals(SALT_LENGTH, generateSalt().size)
        assertEquals(16, generateSalt().size)
    }

    @Test
    fun generateSalt_producesFreshValues() {
        assertFalse(generateSalt().contentEquals(generateSalt()))
    }

    @Test
    fun initIv_usesRecommended12ByteNonceForGcm() {
        // AES-GCM should use a 96-bit (12-byte) nonce.
        assertEquals(12, initIv(CIPHER_ALGORITHM).size)
    }

    @Test
    fun initIv_producesFreshValues() {
        // generated with SecureRandom, so two nonces must not collide.
        assertFalse(initIv(CIPHER_ALGORITHM).contentEquals(initIv(CIPHER_ALGORITHM)))
    }

    // --- AES/GCM round-trip and authentication ------------------------------------------

    @Test
    fun roundTrip_recoversPlaintext() {
        val key = testKey()
        assertArrayEquals(plain, decrypt(key, encrypt(key, plain)))
    }

    @Test
    fun roundTrip_recoversEmptyPlaintext() {
        val key = testKey()
        assertArrayEquals(ByteArray(0), decrypt(key, encrypt(key, ByteArray(0))))
    }

    @Test(expected = IOException::class)
    fun wrongKey_throwsInsteadOfReturningPlaintext() {
        val cipherText = encrypt(testKey("right"), plain)
        // A wrong key makes the GCM tag mismatch; reading to EOF must throw, never return
        // (possibly truncated) plaintext the way CipherInputStream would.
        decrypt(testKey("wrong"), cipherText)
    }

    @Test(expected = IOException::class)
    fun tamperedTag_throws() {
        val cipherText = encrypt(testKey(), plain)
        cipherText[cipherText.size - 1] =
            (cipherText[cipherText.size - 1].toInt() xor 0x01).toByte()
        decrypt(testKey(), cipherText)
    }

    @Test(expected = IOException::class)
    fun tamperedCiphertextMidStream_throws() {
        val large = ByteArray(64 * 1024) { (it and 0xFF).toByte() }
        val cipherText = encrypt(testKey(), large)
        val i = GCM_NONCE_LENGTH + 1024
        cipherText[i] = (cipherText[i].toInt() xor 0xFF).toByte()
        decrypt(testKey(), cipherText)
    }

    @Test(expected = IOException::class)
    fun truncatedCiphertext_throws() {
        val cipherText = encrypt(testKey(), plain)
        // Chop bytes off the end so the GCM tag can no longer be verified.
        decrypt(testKey(), cipherText.copyOf(cipherText.size - 4))
    }

    @Test
    fun eachEncryptionUsesFreshPrependedNonce() {
        val key = testKey()
        val a = encrypt(key, plain)
        val b = encrypt(key, plain)
        val nonceA = a.copyOfRange(0, GCM_NONCE_LENGTH)
        val nonceB = b.copyOfRange(0, GCM_NONCE_LENGTH)
        // Same key + same plaintext must still yield different nonces and ciphertexts,
        // so a nonce is never reused with the same key across a backup's files.
        assertFalse(nonceA.contentEquals(nonceB))
        assertFalse(a.contentEquals(b))
        assertArrayEquals(plain, decrypt(key, a))
        assertArrayEquals(plain, decrypt(key, b))
    }

    @Test(expected = CryptoSetupException::class)
    fun encrypt_withNullKey_throws() {
        ByteArrayOutputStream().encryptStream(null as SecretKey?)
    }

    @Test(expected = CryptoSetupException::class)
    fun decrypt_withNullKey_throws() {
        ByteArrayInputStream(ByteArray(0)).decryptStream(null as SecretKey?)
    }

    // --- password-based stream overloads ------------------------------------------------

    @Test
    fun passwordBased_roundTrips() {
        val bos = ByteArrayOutputStream()
        bos.encryptStream("pw", salt("saltvalue"), iterationCount = 1_000).use { it.write(plain) }
        val recovered = ByteArrayInputStream(bos.toByteArray())
            .decryptStream("pw", salt("saltvalue"), iterationCount = 1_000)
            .use { it.readBytes() }
        assertArrayEquals(plain, recovered)
    }

    @Test(expected = IOException::class)
    fun passwordBased_wrongPassword_throws() {
        val bos = ByteArrayOutputStream()
        bos.encryptStream("right", salt("s"), iterationCount = 1_000).use { it.write(plain) }
        ByteArrayInputStream(bos.toByteArray())
            .decryptStream("wrong", salt("s"), iterationCount = 1_000)
            .use { it.readBytes() }
    }

    @Test(expected = CryptoSetupException::class)
    fun decrypt_streamShorterThanNonce_throws() {
        // Fewer than GCM_NONCE_LENGTH bytes: readNonce cannot fill the nonce and must fail.
        ByteArrayInputStream(ByteArray(4)).decryptStream(testKey())
    }

    // --- initIv for non-GCM ciphers -----------------------------------------------------

    @Test
    fun initIv_usesCipherBlockSizeForNonGcm() {
        assertEquals(16, initIv("AES/CBC/PKCS5Padding").size)
    }

    @Test
    fun initIv_fallsBackToDefaultForUnknownCipher() {
        // Unknown algorithm -> NoSuchAlgorithmException -> DEFAULT_IV_BLOCK_SIZE (32 bytes).
        assertEquals(32, initIv("NoSuchCipher/XYZ/NoPadding").size)
    }

    // --- streaming edge cases -----------------------------------------------------------

    @Test
    fun encrypt_supportsByteByByteWriteAndFlush() {
        val key = testKey()
        val bos = ByteArrayOutputStream()
        bos.encryptStream(key).use { out ->
            for (b in plain) out.write(b.toInt())
            out.flush()
        }
        assertArrayEquals(plain, decrypt(key, bos.toByteArray()))
    }

    @Test
    fun decrypt_readZeroLength_returnsZeroAndLeavesStreamReadable() {
        val key = testKey()
        ByteArrayInputStream(encrypt(key, plain)).decryptStream(key).use { ins ->
            assertEquals(0, ins.read(ByteArray(4), 0, 0))
            assertArrayEquals(plain, ins.readBytes())
        }
    }

    @Test
    fun decrypt_partialReadThenClose_verifiesValidDataWithoutError() {
        val large = ByteArray(64 * 1024) { (it and 0xFF).toByte() }
        val key = testKey()
        val ins = ByteArrayInputStream(encrypt(key, large)).decryptStream(key)
        assertTrue(ins.read() >= 0)   // consume only one byte
        ins.close()                   // close must drain & verify the remaining ciphertext
    }

    @Test(expected = IOException::class)
    fun decrypt_partialReadThenClose_onTamperedData_throws() {
        val large = ByteArray(64 * 1024) { (it and 0xFF).toByte() }
        val key = testKey()
        val cipherText = encrypt(key, large)
        val i = GCM_NONCE_LENGTH + 2048
        cipherText[i] = (cipherText[i].toInt() xor 0xFF).toByte()
        val ins = ByteArrayInputStream(cipherText).decryptStream(key)
        ins.read()      // read one byte, so the stream is not finalized yet
        ins.close()     // draining the rest on close must detect the bad tag
    }

    @Test
    fun decrypt_readSingleBytesToEof_thenStaysAtEof() {
        val key = testKey()
        val ins = ByteArrayInputStream(encrypt(key, plain)).decryptStream(key)
        val out = ByteArrayOutputStream()
        var b = ins.read()
        while (b >= 0) {
            out.write(b)
            b = ins.read()          // drive read() all the way to end-of-stream
        }
        assertEquals(-1, ins.read()) // stays at EOF once finalized
        ins.close()                  // already finalized -> close is a no-op drain
        assertArrayEquals(plain, out.toByteArray())
    }
}
