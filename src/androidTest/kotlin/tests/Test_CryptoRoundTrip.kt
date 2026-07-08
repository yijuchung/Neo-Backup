package tests.tests

import com.machiav3lli.backup.utils.CryptoSetupException
import com.machiav3lli.backup.utils.GCM_NONCE_LENGTH
import com.machiav3lli.backup.utils.decryptStream
import com.machiav3lli.backup.utils.encryptStream
import com.machiav3lli.backup.utils.generateKeyFromPassword
import com.machiav3lli.backup.utils.generateSalt
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertFalse
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import javax.crypto.SecretKey

/**
 * Instrumented round-trip tests for the AES/GCM backup encryption, running on-device against
 * the real Android crypto provider (Conscrypt), which - unlike the desktop SunJCE provider -
 * may release plaintext incrementally before the tag is verified.
 *
 * It verifies the happy-path round-trip, that a wrong password never recovers the plaintext,
 * that tampering/truncation is surfaced as an error instead of being silently accepted as
 * plaintext (the CipherInputStream pitfall), and that every file gets a fresh prepended nonce.
 */
class Test_CryptoRoundTrip {

    private val password = "test-password"
    private val salt = generateSalt()
    private val plain = "secret backup payload — 1234567890".toByteArray(Charsets.UTF_8)

    // Lower-than-default iterations keep the instrumented run quick; the KDF cost is asserted
    // in the local unit tests.
    private fun key(pw: String = password): SecretKey =
        generateKeyFromPassword(pw, salt, iterationCount = 10_000)

    private fun encrypt(key: SecretKey, data: ByteArray = plain): ByteArray {
        val bos = ByteArrayOutputStream()
        bos.encryptStream(key).use { it.write(data) }
        return bos.toByteArray()
    }

    private fun decrypt(key: SecretKey, cipherText: ByteArray): ByteArray =
        ByteArrayInputStream(cipherText).decryptStream(key).use { it.readBytes() }

    @Test
    fun roundTrip_recoversPlaintext() {
        val key = key()
        assertArrayEquals(plain, decrypt(key, encrypt(key)))
    }

    @Test(expected = IOException::class)
    fun wrongPassword_throwsInsteadOfRecoveringPlaintext() {
        val cipherText = encrypt(key("right-password"))
        decrypt(key("wrong-password"), cipherText)
    }

    @Test(expected = IOException::class)
    fun tamperedCiphertext_throws() {
        val cipherText = encrypt(key())
        cipherText[cipherText.size - 1] =
            (cipherText[cipherText.size - 1].toInt() xor 0x01).toByte()
        decrypt(key(), cipherText)
    }

    @Test(expected = IOException::class)
    fun truncatedCiphertext_throws() {
        val cipherText = encrypt(key())
        decrypt(key(), cipherText.copyOf(cipherText.size - 4))
    }

    @Test
    fun eachEncryptionUsesFreshPrependedNonce() {
        val key = key()
        val a = encrypt(key)
        val b = encrypt(key)
        assertFalse(
            a.copyOfRange(0, GCM_NONCE_LENGTH).contentEquals(b.copyOfRange(0, GCM_NONCE_LENGTH))
        )
        assertFalse(a.contentEquals(b))
        assertArrayEquals(plain, decrypt(key, a))
        assertArrayEquals(plain, decrypt(key, b))
    }

    @Test(expected = CryptoSetupException::class)
    fun encrypt_withNullKey_throws() {
        ByteArrayOutputStream().encryptStream(null as SecretKey?)
    }
}
