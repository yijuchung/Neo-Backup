package com.machiav3lli.backup.utils

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Local-JVM unit tests for [PrefValueCodec], the pure value<->string serialization used by the
 * Keystore-backed private preferences. Covers primitive encode/decode round-trips, default
 * fallback on null/malformed input, and the NUL-separated string-set encoding.
 */
class PrefValueCodecTest {

    // --- primitive round-trips ----------------------------------------------------------

    @Test
    fun int_roundTrips() {
        assertEquals(42, PrefValueCodec.decodeInt(PrefValueCodec.encode(42), -1))
        assertEquals(-7, PrefValueCodec.decodeInt(PrefValueCodec.encode(-7), 0))
    }

    @Test
    fun long_roundTrips() {
        val v = 9_876_543_210L
        assertEquals(v, PrefValueCodec.decodeLong(PrefValueCodec.encode(v), 0L))
    }

    @Test
    fun float_roundTrips() {
        assertEquals(3.5f, PrefValueCodec.decodeFloat(PrefValueCodec.encode(3.5f), 0f), 0f)
    }

    @Test
    fun boolean_roundTrips() {
        assertTrue(PrefValueCodec.decodeBoolean(PrefValueCodec.encode(true), false))
        assertEquals(false, PrefValueCodec.decodeBoolean(PrefValueCodec.encode(false), true))
    }

    // --- default fallback on null / malformed input -------------------------------------

    @Test
    fun decode_null_returnsDefault() {
        assertEquals(11, PrefValueCodec.decodeInt(null, 11))
        assertEquals(12L, PrefValueCodec.decodeLong(null, 12L))
        assertEquals(1.5f, PrefValueCodec.decodeFloat(null, 1.5f), 0f)
        assertTrue(PrefValueCodec.decodeBoolean(null, true))
        assertNull(PrefValueCodec.decodeStringSet(null))
    }

    @Test
    fun decode_malformed_returnsDefault() {
        assertEquals(99, PrefValueCodec.decodeInt("not-a-number", 99))
        assertEquals(98L, PrefValueCodec.decodeLong("NaN-long", 98L))
        assertEquals(9.9f, PrefValueCodec.decodeFloat("xyz", 9.9f), 0f)
        // toBooleanStrictOrNull only accepts exactly "true"/"false".
        assertTrue(PrefValueCodec.decodeBoolean("TRUE", true))
        assertEquals(false, PrefValueCodec.decodeBoolean("yes", false))
    }

    // --- string set encoding ------------------------------------------------------------

    @Test
    fun stringSet_roundTrips() {
        val set = setOf("alpha", "beta", "gamma")
        val decoded = PrefValueCodec.decodeStringSet(PrefValueCodec.encodeStringSet(set))
        assertEquals(set, decoded)
    }

    @Test
    fun stringSet_empty_encodesToEmptyAndDecodesToEmptySet() {
        val encoded = PrefValueCodec.encodeStringSet(emptySet())
        assertEquals("", encoded)
        assertEquals(mutableSetOf<String>(), PrefValueCodec.decodeStringSet(encoded))
    }

    @Test
    fun stringSet_dropsEmptyFragments() {
        // A trailing/leading separator must not introduce a phantom empty member.
        val encoded = "a${PrefValueCodec.STRING_SET_SEPARATOR}${PrefValueCodec.STRING_SET_SEPARATOR}b"
        assertEquals(mutableSetOf("a", "b"), PrefValueCodec.decodeStringSet(encoded))
    }

    @Test
    fun stringSet_preservesValuesContainingSpacesAndUnicode() {
        val set = setOf("com.example.app", "a b c", "naïve — value")
        val decoded = PrefValueCodec.decodeStringSet(PrefValueCodec.encodeStringSet(set))
        assertEquals(set, decoded)
    }
}
