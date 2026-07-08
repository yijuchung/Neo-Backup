package com.machiav3lli.backup.utils

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.nio.charset.StandardCharsets

/**
 * Unit tests for the parts of CryptoUtils that are provider-independent and run on
 * the local JVM: password-based key derivation ([generateKeyFromPassword]) and
 * IV/nonce generation ([initIv]).
 *
 * The full AES/GCM encrypt/decrypt round-trip depends on the Android crypto provider
 * (Conscrypt accepts an IvParameterSpec for GCM, the desktop SunJCE provider does not),
 * so that is covered by an instrumented test instead.
 */
class CryptoUtilsTest {

    private fun salt(s: String) = s.toByteArray(StandardCharsets.UTF_8)

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
        // Rationale for F6: a constant/shared salt lets keys be precomputed across
        // users/backups. Different salts must yield different keys.
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
    fun initIv_usesRecommended12ByteNonceForGcm() {
        // F9: AES-GCM should use a 96-bit (12-byte) nonce.
        val iv = initIv(CIPHER_ALGORITHM)
        assertEquals(12, iv.size)
    }

    @Test
    fun initIv_producesFreshValues() {
        // F9: generated with SecureRandom, so two nonces must not collide.
        val a = initIv(CIPHER_ALGORITHM)
        val b = initIv(CIPHER_ALGORITHM)
        assertFalse(a.contentEquals(b))
    }
}
