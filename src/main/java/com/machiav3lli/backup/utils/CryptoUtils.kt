/*
 * OAndBackupX: open-source apps backup and restore app.
 * Copyright (C) 2020  Antonios Hazim
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
package com.machiav3lli.backup.utils

import timber.log.Timber
import java.io.File
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.security.GeneralSecurityException
import java.security.NoSuchAlgorithmException
import java.security.SecureRandom
import java.security.spec.InvalidKeySpecException
import java.security.spec.KeySpec
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.NoSuchPaddingException
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

/**
 * Crypto. The class to handle encryption and decryption of streams.
 * Call `encryptStream` or `decryptStream` with a derived [SecretKey] (preferred) or a
 * password and its per-backup key-derivation parameters, and the class will wrap the given
 * stream in return.
 *
 * Android Keystore API is not used on purpose, because the key material needs to be portable for
 * use cases when the device has been wiped or when backups are restored on another device.
 *
 * Each encrypted archive is authenticated end to end with AES-GCM:
 *  - a fresh, cryptographically random 96-bit nonce is generated per file and stored as a
 *    fixed-size prefix of the ciphertext, so a nonce is never reused with the same key;
 *  - decryption verifies the 128-bit GCM authentication tag and propagates
 *    [AEADBadTagException] instead of silently returning truncated plaintext the way
 *    [javax.crypto.CipherInputStream] does.
 */

private const val ENCRYPTION_SETUP_FAILED = "Could not setup encryption"

/**
 * https://developer.android.com/guide/topics/security/cryptography#Cipher
 * Starting SDK28 ChaCha20 is supported, which is far more faster than standard AES
 * Maybe will implement it in the future as an option AES/ChaCha20
 *
 * The original choice was inspired by this blog post:
 * https://www.raywenderlich.com/778533-encryption-tutorial-for-android-getting-started
 */
const val DEFAULT_SECRET_KEY_FACTORY_ALGORITHM = "PBKDF2withHmacSHA256"
const val CIPHER_ALGORITHM = "AES/GCM/NoPadding"
private const val DEFAULT_IV_BLOCK_SIZE = 32 // 256 bit
const val GCM_NONCE_LENGTH = 12 // 96 bit, recommended nonce size for AES-GCM
const val GCM_TAG_LENGTH_BITS = 128 // 128 bit authentication tag, the AES-GCM maximum
const val DEFAULT_KEY_LENGTH = 256

/**
 * PBKDF2 work factor. Raised far above the legacy value (2020) to the OWASP 2023
 * recommendation for PBKDF2-HMAC-SHA256. The key is derived once per backup (not once per
 * file), so this stays affordable. The actual value used is recorded per backup so a backup
 * stays decryptable even if this default changes later.
 */
const val ITERATION_COUNT = 600_000

/** Length of the random per-backup salt, in bytes (128 bit). */
const val SALT_LENGTH = 16

/** Generates a fresh, cryptographically random salt for password-based key derivation. */
fun generateSalt(length: Int = SALT_LENGTH): ByteArray =
    ByteArray(length).also { SecureRandom().nextBytes(it) }

@Throws(NoSuchAlgorithmException::class, InvalidKeySpecException::class)
fun generateKeyFromPassword(
    password: String,
    salt: ByteArray?,
    iterationCount: Int = ITERATION_COUNT,
    keyLength: Int = DEFAULT_KEY_LENGTH,
    keyFactoryAlgorithm: String = DEFAULT_SECRET_KEY_FACTORY_ALGORITHM,
    cipherAlgorithm: String = CIPHER_ALGORITHM,
): SecretKey {
    val factory = SecretKeyFactory.getInstance(keyFactoryAlgorithm)
    val spec: KeySpec = PBEKeySpec(password.toCharArray(), salt, iterationCount, keyLength)
    val keyBytes = factory.generateSecret(spec).encoded
    return SecretKeySpec(keyBytes, cipherAlgorithm.split(File.separator).toTypedArray()[0])
}

class CryptoSetupException(cause: Throwable? = null) : Exception(ENCRYPTION_SETUP_FAILED, cause)

fun handleCryptoException(e: Throwable): Throwable {
    Timber.e("$ENCRYPTION_SETUP_FAILED: ${e.message}")
    return CryptoSetupException(e)
}

@Throws(CryptoSetupException::class)
fun OutputStream.encryptStream(
    password: String,
    salt: ByteArray?,
    iterationCount: Int = ITERATION_COUNT,
    keyLength: Int = DEFAULT_KEY_LENGTH,
): OutputStream = try {
    val secret = generateKeyFromPassword(password, salt, iterationCount, keyLength)
    this.encryptStream(secret)
} catch (e: GeneralSecurityException) {
    throw handleCryptoException(e)
}

@Throws(CryptoSetupException::class)
fun OutputStream.encryptStream(
    secret: SecretKey?,
    cipherAlgorithm: String = CIPHER_ALGORITHM,
    gcmTagLengthBits: Int = GCM_TAG_LENGTH_BITS,
): OutputStream = try {
    if (secret == null)
        throw CryptoSetupException(IllegalArgumentException("Missing key for encryption"))
    // A unique nonce per (key, message) is mandatory for AES-GCM. Generate a fresh one for
    // every file and store it as a fixed-size, non-secret prefix so each archive is
    // self-describing and no nonce is ever reused across the files of a backup.
    val nonce = initIv(cipherAlgorithm)
    this.write(nonce)
    val cipher = Cipher.getInstance(cipherAlgorithm)
    cipher.init(Cipher.ENCRYPT_MODE, secret, GCMParameterSpec(gcmTagLengthBits, nonce))
    GcmCipherOutputStream(this, cipher)
} catch (e: GeneralSecurityException) {
    throw handleCryptoException(e)
} catch (e: IOException) {
    throw handleCryptoException(e)
}

@Throws(CryptoSetupException::class)
fun InputStream.decryptStream(
    password: String,
    salt: ByteArray?,
    iterationCount: Int = ITERATION_COUNT,
    keyLength: Int = DEFAULT_KEY_LENGTH,
): InputStream = try {
    val secret = generateKeyFromPassword(password, salt, iterationCount, keyLength)
    decryptStream(secret)
} catch (e: GeneralSecurityException) {
    throw handleCryptoException(e)
}

@Throws(CryptoSetupException::class)
fun InputStream.decryptStream(
    secret: SecretKey?,
    cipherAlgorithm: String = CIPHER_ALGORITHM,
    gcmTagLengthBits: Int = GCM_TAG_LENGTH_BITS,
): InputStream = try {
    if (secret == null)
        throw CryptoSetupException(IllegalArgumentException("Missing key for decryption"))
    val nonce = readNonce(this, cipherAlgorithm)
    val cipher = Cipher.getInstance(cipherAlgorithm)
    cipher.init(Cipher.DECRYPT_MODE, secret, GCMParameterSpec(gcmTagLengthBits, nonce))
    GcmVerifyingInputStream(this, cipher)
} catch (e: GeneralSecurityException) {
    throw handleCryptoException(e)
} catch (e: IOException) {
    throw handleCryptoException(e)
}

fun initIv(cipherAlgorithm: String): ByteArray {
    val size: Int = if (cipherAlgorithm.contains("GCM")) {
        // AES-GCM: use the recommended 96-bit nonce.
        GCM_NONCE_LENGTH
    } else try {
        val cipher = Cipher.getInstance(cipherAlgorithm)
        cipher.blockSize
    } catch (e: NoSuchAlgorithmException) {
        // Fallback if the cipher has issues. Might lead to another exception later, but saves
        // the situation here. The use cipher might not match or will cause other exceptions
        // when used like this.
        DEFAULT_IV_BLOCK_SIZE
    } catch (e: NoSuchPaddingException) {
        DEFAULT_IV_BLOCK_SIZE
    }
    // The IV/nonce is not secret, but for AES-GCM it MUST be unique per key and unpredictable,
    // so it is generated with a cryptographically secure RNG rather than kotlin.random.Random.
    return ByteArray(size).also { SecureRandom().nextBytes(it) }
}

/** Reads the fixed-size nonce that [encryptStream] prepends to the ciphertext. */
@Throws(IOException::class)
private fun readNonce(input: InputStream, cipherAlgorithm: String): ByteArray {
    val size = if (cipherAlgorithm.contains("GCM")) GCM_NONCE_LENGTH else DEFAULT_IV_BLOCK_SIZE
    val nonce = ByteArray(size)
    var read = 0
    while (read < size) {
        val n = input.read(nonce, read, size - read)
        if (n < 0)
            throw IOException("Encrypted stream is too short to contain the $size-byte nonce")
        read += n
    }
    return nonce
}

/**
 * AES-GCM output stream that guarantees the authentication tag is written and that any error
 * during finalization is propagated (unlike [javax.crypto.CipherOutputStream], whose close()
 * can swallow exceptions).
 */
private class GcmCipherOutputStream(
    private val sink: OutputStream,
    private val cipher: Cipher,
) : OutputStream() {

    private var closed = false

    override fun write(b: Int) {
        cipher.update(byteArrayOf(b.toByte()))?.let { if (it.isNotEmpty()) sink.write(it) }
    }

    override fun write(b: ByteArray, off: Int, len: Int) {
        if (len == 0) return
        cipher.update(b, off, len)?.let { if (it.isNotEmpty()) sink.write(it) }
    }

    override fun flush() {
        sink.flush()
    }

    override fun close() {
        if (closed) return
        closed = true
        try {
            // doFinal() emits any buffered ciphertext plus the GCM authentication tag.
            val fin = cipher.doFinal()
            if (fin != null && fin.isNotEmpty()) sink.write(fin)
            sink.flush()
        } catch (e: GeneralSecurityException) {
            throw IOException("Encryption finalization failed", e)
        } finally {
            sink.close()
        }
    }
}

/**
 * AES-GCM input stream that decrypts on the fly and, critically, verifies the authentication
 * tag by calling [Cipher.doFinal] once the whole ciphertext has been consumed. A tag mismatch
 * (tampered or truncated archive) is surfaced as an [IOException] instead of being silently
 * swallowed the way [javax.crypto.CipherInputStream] does.
 *
 * Verification is guaranteed: it happens either when the reader reaches end-of-stream, or, if
 * the reader stops early, when [close] drains and finalizes the remaining ciphertext.
 */
private class GcmVerifyingInputStream(
    private val source: InputStream,
    private val cipher: Cipher,
) : InputStream() {

    private val readBuf = ByteArray(16 * 1024)
    private var buffer: ByteArray = EMPTY
    private var pos = 0
    private var sourceEof = false
    private var finalized = false

    /** Ensures [buffer] holds unread plaintext, or returns false at true end-of-stream. */
    @Throws(IOException::class)
    private fun fill(): Boolean {
        while (pos >= buffer.size) {
            if (finalized) return false
            if (sourceEof) {
                buffer = doFinalVerifying()
                pos = 0
                finalized = true
            } else {
                val n = source.read(readBuf)
                if (n < 0) {
                    sourceEof = true
                } else if (n > 0) {
                    buffer = cipher.update(readBuf, 0, n) ?: EMPTY
                    pos = 0
                }
            }
        }
        return true
    }

    @Throws(IOException::class)
    private fun doFinalVerifying(): ByteArray = try {
        cipher.doFinal() ?: EMPTY
    } catch (e: AEADBadTagException) {
        throw IOException("AES-GCM authentication tag verification failed", e)
    } catch (e: GeneralSecurityException) {
        throw IOException("Decryption finalization failed", e)
    }

    @Throws(IOException::class)
    override fun read(): Int {
        if (!fill()) return -1
        return buffer[pos++].toInt() and 0xFF
    }

    @Throws(IOException::class)
    override fun read(b: ByteArray, off: Int, len: Int): Int {
        if (len == 0) return 0
        if (!fill()) return -1
        val n = minOf(len, buffer.size - pos)
        System.arraycopy(buffer, pos, b, off, n)
        pos += n
        return n
    }

    @Throws(IOException::class)
    override fun close() {
        try {
            if (!finalized) {
                // Feed any ciphertext the reader did not consume so the tag covers the whole
                // message, then verify it. Guarantees authentication even on partial reads.
                while (!sourceEof) {
                    val n = source.read(readBuf)
                    if (n < 0) sourceEof = true
                    else if (n > 0) cipher.update(readBuf, 0, n)
                }
                doFinalVerifying()
                finalized = true
            }
        } finally {
            source.close()
        }
    }

    companion object {
        private val EMPTY = ByteArray(0)
    }
}
