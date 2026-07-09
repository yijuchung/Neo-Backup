/*
 * Neo Backup: open-source apps backup and restore app.
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

/**
 * Pure, dependency-free codec that converts typed preference values to and from the single string
 * form that [KeystoreEncryptedPreferences] encrypts at rest.
 *
 * Splitting the serialization out of the encryption keeps the "how a value is represented" concern
 * testable on the plain JVM (see PrefValueCodecTest) while [KeystoreEncryptedPreferences] is left
 * with only the Android-Keystore-specific crypto. Decoders take the caller's default and return it
 * on `null` or malformed input, exactly matching the [android.content.SharedPreferences] contract.
 */
object PrefValueCodec {

    /**
     * Separator used to flatten a string set into one string. NUL can never appear inside an
     * Android preference key/value coming through the normal APIs, so it round-trips safely.
     */
    const val STRING_SET_SEPARATOR = "\u0000"

    fun encode(value: Int): String = value.toString()
    fun encode(value: Long): String = value.toString()
    fun encode(value: Float): String = value.toString()
    fun encode(value: Boolean): String = value.toString()

    fun encodeStringSet(values: Set<String>): String =
        values.joinToString(STRING_SET_SEPARATOR)

    fun decodeInt(stored: String?, defValue: Int): Int = stored?.toIntOrNull() ?: defValue

    fun decodeLong(stored: String?, defValue: Long): Long = stored?.toLongOrNull() ?: defValue

    fun decodeFloat(stored: String?, defValue: Float): Float = stored?.toFloatOrNull() ?: defValue

    fun decodeBoolean(stored: String?, defValue: Boolean): Boolean =
        stored?.toBooleanStrictOrNull() ?: defValue

    /** Empty fragments are dropped so an empty set and a single empty string can't be confused. */
    fun decodeStringSet(stored: String?): MutableSet<String>? =
        stored?.split(STRING_SET_SEPARATOR)
            ?.filter { it.isNotEmpty() }
            ?.toMutableSet()
}
