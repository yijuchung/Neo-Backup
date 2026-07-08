package tests.tests

import com.machiav3lli.backup.utils.CIPHER_ALGORITHM
import com.machiav3lli.backup.utils.CryptoSetupException
import com.machiav3lli.backup.utils.decryptStream
import com.machiav3lli.backup.utils.encryptStream
import com.machiav3lli.backup.utils.initIv
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertFalse
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream

/**
 * Instrumented round-trip tests for the AES/GCM backup encryption.
 *
 * This runs on-device because the streaming GCM cipher relies on the Android
 * crypto provider (Conscrypt). It verifies the happy-path round-trip, that a wrong
 * password never recovers the plaintext, that tampering is not silently accepted as
 * valid plaintext (F8), and that the IV guards added for F7 reject a missing IV.
 */
class Test_CryptoRoundTrip {

    private val password = "test-password"
    private val salt = "test-salt".toByteArray(Charsets.UTF_8)
    private val plain = "secret backup payload — 1234567890".toByteArray(Charsets.UTF_8)

    private fun encrypt(iv: ByteArray): ByteArray {
        val bos = ByteArrayOutputStream()
        bos.encryptStream(password, salt, iv).use { it.write(plain) }
        return bos.toByteArray()
    }

    private fun tryDecrypt(cipherText: ByteArray, pw: String, iv: ByteArray): ByteArray? = try {
        ByteArrayInputStream(cipherText).decryptStream(pw, salt, iv).use { it.readBytes() }
    } catch (e: Exception) {
        null
    }

    @Test
    fun roundTrip_recoversPlaintext() {
        val iv = initIv(CIPHER_ALGORITHM)
        val cipherText = encrypt(iv)
        val decrypted = tryDecrypt(cipherText, password, iv)
        assertArrayEquals(plain, decrypted)
    }

    @Test
    fun wrongPassword_doesNotRecoverPlaintext() {
        val iv = initIv(CIPHER_ALGORITHM)
        val cipherText = encrypt(iv)
        val decrypted = tryDecrypt(cipherText, "wrong-password", iv)
        assertFalse(decrypted != null && plain.contentEquals(decrypted))
    }

    @Test
    fun tamperedCiphertext_isNotAcceptedAsPlaintext() {
        val iv = initIv(CIPHER_ALGORITHM)
        val cipherText = encrypt(iv)
        cipherText[cipherText.size - 1] = (cipherText[cipherText.size - 1].toInt() xor 0x01).toByte()
        val decrypted = tryDecrypt(cipherText, password, iv)
        assertFalse(decrypted != null && plain.contentEquals(decrypted))
    }

    @Test(expected = CryptoSetupException::class)
    fun decrypt_withNullIv_throws() {
        ByteArrayInputStream(ByteArray(0)).decryptStream(password, salt, null)
    }

    @Test(expected = CryptoSetupException::class)
    fun encrypt_withNullIv_throws() {
        ByteArrayOutputStream().encryptStream(password, salt, null)
    }
}
