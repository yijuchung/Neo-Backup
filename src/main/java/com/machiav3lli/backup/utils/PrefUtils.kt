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

import android.app.KeyguardManager
import android.content.Context
import android.content.SharedPreferences
import android.net.Uri
import android.provider.DocumentsContract
import androidx.biometric.BiometricManager
import androidx.preference.PreferenceManager
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import com.machiav3lli.backup.ENCRYPTION
import com.machiav3lli.backup.NeoApp
import com.machiav3lli.backup.PREFS_LANGUAGES_SYSTEM
import com.machiav3lli.backup.PREFS_SHARED_PRIVATE
import com.machiav3lli.backup.R
import com.machiav3lli.backup.config.BuildConfig
import com.machiav3lli.backup.data.entity.StorageFile
import com.machiav3lli.backup.manager.handler.LogsHandler.Companion.logException
import com.machiav3lli.backup.manager.tasks.RefreshBackupsWorker
import com.machiav3lli.backup.ui.pages.pref_allowDowngrade
import com.machiav3lli.backup.ui.pages.pref_appAccentColor
import com.machiav3lli.backup.ui.pages.pref_appSecondaryColor
import com.machiav3lli.backup.ui.pages.pref_appTheme
import com.machiav3lli.backup.ui.pages.pref_backupDeviceProtectedData
import com.machiav3lli.backup.ui.pages.pref_backupExternalData
import com.machiav3lli.backup.ui.pages.pref_backupMediaData
import com.machiav3lli.backup.ui.pages.pref_backupObbData
import com.machiav3lli.backup.ui.pages.pref_biometricLock
import com.machiav3lli.backup.ui.pages.pref_compressionLevel
import com.machiav3lli.backup.ui.pages.pref_compressionType
import com.machiav3lli.backup.ui.pages.pref_deviceLock
import com.machiav3lli.backup.ui.pages.pref_disableVerification
import com.machiav3lli.backup.ui.pages.pref_enableSpecialBackups
import com.machiav3lli.backup.ui.pages.pref_encryption_mode
import com.machiav3lli.backup.ui.pages.pref_giveAllPermissions
import com.machiav3lli.backup.ui.pages.pref_languages
import com.machiav3lli.backup.ui.pages.pref_password
import com.machiav3lli.backup.ui.pages.pref_pathBackupFolder
import com.machiav3lli.backup.ui.pages.pref_pgpPasscode
import com.machiav3lli.backup.ui.pages.pref_restoreDeviceProtectedData
import com.machiav3lli.backup.ui.pages.pref_restoreExternalData
import com.machiav3lli.backup.ui.pages.pref_restoreMediaData
import com.machiav3lli.backup.ui.pages.pref_restoreObbData
import com.machiav3lli.backup.ui.pages.pref_shadowRootFile
import timber.log.Timber
import java.io.File
import java.util.Locale

const val READ_PERMISSION = 2
const val WRITE_PERMISSION = 3
const val SMS_PERMISSION = 4
const val CONTACTS_PERMISSION = 5
const val CALLLOGS_PERMISSION = 6

// Keystore-backed private-prefs vault (replaces androidx.security EncryptedSharedPreferences).
private const val PREFS_SHARED_PRIVATE_V2 = "com.machiav3lli.backup.private.v2"
private const val PRIVATE_PREFS_KEY_ALIAS = "NeoBackupPrivatePrefsKey"
private const val PRIVATE_PREFS_MIGRATED_FLAG = "persist.privatePrefsMigratedToKeystore"

fun Context.getDefaultSharedPreferences(): SharedPreferences =
    PreferenceManager.getDefaultSharedPreferences(this)

fun Context.getPrivateSharedPrefs(): SharedPreferences {
    val backing = getSharedPreferences(PREFS_SHARED_PRIVATE_V2, Context.MODE_PRIVATE)
    val prefs = KeystoreEncryptedPreferences(backing, PRIVATE_PREFS_KEY_ALIAS)
    migrateLegacyPrivatePrefs(prefs)
    return prefs
}

/**
 * One-time transitional migration off the deprecated `androidx.security:security-crypto`
 * library. If the legacy `EncryptedSharedPreferences` vault file is present and this migration
 * has not run yet, its entries are read once and copied into the Keystore-backed
 * [KeystoreEncryptedPreferences], then a flag is set so it never runs again.
 *
 * This is intentionally the ONLY remaining use of `androidx.security.crypto` in the app: the
 * runtime read/write path uses [KeystoreEncryptedPreferences] exclusively. The dependency is
 * kept solely for this read path and can be dropped in a future release.
 */
private fun Context.migrateLegacyPrivatePrefs(target: KeystoreEncryptedPreferences) {
    val flags = getDefaultSharedPreferences()
    if (flags.getBoolean(PRIVATE_PREFS_MIGRATED_FLAG, false)) return
    try {
        val legacyFile = File(
            File(applicationInfo.dataDir, "shared_prefs"),
            "$PREFS_SHARED_PRIVATE.xml"
        )
        if (!legacyFile.exists()) {
            // Nothing to migrate (fresh install, or the legacy vault was never created).
            flags.edit().putBoolean(PRIVATE_PREFS_MIGRATED_FLAG, true).apply()
            return
        }
        val masterKey = MasterKey.Builder(this)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()
        val legacy = EncryptedSharedPreferences.create(
            this,
            PREFS_SHARED_PRIVATE,
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
        )
        val entries = legacy.all
        val editor = target.edit()
        entries.forEach { (key, value) ->
            when (value) {
                is String  -> editor.putString(key, value)
                is Boolean -> editor.putBoolean(key, value)
                is Int     -> editor.putInt(key, value)
                is Long    -> editor.putLong(key, value)
                is Float   -> editor.putFloat(key, value)
                is Set<*>  -> editor.putStringSet(
                    key,
                    value.filterIsInstance<String>().toMutableSet(),
                )
            }
        }
        // commit() (not apply()) so the re-encrypted values are on disk before we set the
        // one-shot flag; otherwise a crash between the two writes could drop the password.
        if (editor.commit()) {
            flags.edit().putBoolean(PRIVATE_PREFS_MIGRATED_FLAG, true).apply()
            Timber.i("Migrated ${entries.size} private preference(s) to the Keystore vault")
        }
    } catch (e: Throwable) {
        // Leave the flag unset so a later launch can retry; never lose the saved password on a
        // transient keystore/decryption error.
        logException(e, "Could not migrate legacy private preferences to the Keystore vault")
    }
}

fun isEncryptionEnabled(): Boolean =
    pref_encryption_mode.value != ENCRYPTION.NONE.ordinal && getEncryptionPassword().isNotEmpty()

fun isPasswordEncryptionEnabled(): Boolean =
    pref_encryption_mode.value == ENCRYPTION.PASSWORD.ordinal && getEncryptionPassword().isNotEmpty()

fun isPGPEncryptionEnabled(): Boolean =
    pref_encryption_mode.value == ENCRYPTION.PGP.ordinal && getEncryptionPassword().isNotEmpty()

fun getEncryptionPassword(): String = when (pref_encryption_mode.value) {
    ENCRYPTION.PASSWORD.ordinal -> pref_password.value
    ENCRYPTION.PGP.ordinal      -> pref_pgpPasscode.value
    else                        -> ""
}

fun isCompressionEnabled(): Boolean =
    getCompressionType().isNotEmpty() && getCompressionLevel() > 0

fun getCompressionType(): String = pref_compressionType.value

fun getCompressionLevel() = pref_compressionLevel.value

fun isDeviceLockEnabled(): Boolean = pref_deviceLock.value

fun Context.isDeviceLockAvailable(): Boolean =
    (getSystemService(KeyguardManager::class.java) as KeyguardManager).isDeviceSecure

fun isBiometricLockEnabled(): Boolean = pref_biometricLock.value

fun Context.isBiometricLockAvailable(): Boolean =
    BiometricManager.from(this).canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_WEAK) ==
            BiometricManager.BIOMETRIC_SUCCESS


val backupDirConfigured: String
    get() {
        val location = pref_pathBackupFolder.value
        if (location.isEmpty())
            throw StorageLocationNotConfiguredException()
        return location
    }

fun backupFolderExists(uri: String? = null): Boolean {
    try {
        uri?.let {
            if (StorageFile.fromUri(it).exists())
                return true
        }
        if (NeoApp.backupRoot?.exists() ?: false)
            return true
    } catch (e: Throwable) {
        logException(e)
        return false
    }
    return false
}

fun setBackupDir(uri: Uri): String {
    val fullUri = try {
        DocumentsContract
            .buildDocumentUriUsingTree(uri, DocumentsContract.getTreeDocumentId(uri))
    } catch (e: Throwable) {
        uri
    }
    val fullUriString = fullUri.toString()
    if (pref_pathBackupFolder.value != fullUriString)
        pref_pathBackupFolder.value = fullUriString
    else {
        if (fullUri.scheme == "file" || fullUri.scheme == null)
            if (!pref_shadowRootFile.value) // prevent recursion
                pref_shadowRootFile.value = true
        RefreshBackupsWorker.enqueueFullRefresh()
    }
    return fullUriString
}

val Context.canReadExternalStorage: Boolean
    get() {
        val externalStorage = FileUtils.getExternalStorageDirectory(this)
        return externalStorage?.canRead() ?: false
    }

val Context.canWriteExternalStorage: Boolean
    get() {
        val externalStorage = FileUtils.getExternalStorageDirectory(this)
        return externalStorage?.canWrite() ?: false
    }

val isBackupDeviceProtectedData: Boolean
    get() = pref_backupDeviceProtectedData.value

val isBackupExternalData: Boolean
    get() = pref_backupExternalData.value

val isBackupObbData: Boolean
    get() = pref_backupObbData.value

val isBackupMediaData: Boolean
    get() = pref_backupMediaData.value

val isRestoreDeviceProtectedData: Boolean
    get() = pref_restoreDeviceProtectedData.value

val isRestoreExternalData: Boolean
    get() = pref_restoreExternalData.value

val isRestoreObbData: Boolean
    get() = pref_restoreObbData.value

val isRestoreMediaData: Boolean
    get() = pref_restoreMediaData.value

val isDisableVerification: Boolean
    get() = pref_disableVerification.value

val isRestoreAllPermissions: Boolean
    get() = pref_giveAllPermissions.value

val isAllowDowngrade: Boolean
    get() = pref_allowDowngrade.value

class StorageLocationNotConfiguredException : Exception("Storage Location has not been configured")

var styleTheme: Int
    get() = pref_appTheme.value
    set(value) {
        pref_appTheme.value = value
    }

var stylePrimary: Int
    get() = pref_appAccentColor.value
    set(value) {
        pref_appAccentColor.value = value
    }

var styleSecondary: Int
    get() = pref_appSecondaryColor.value
    set(value) {
        pref_appSecondaryColor.value = value
    }

var language: String
    get() = pref_languages.value
    set(value) {
        pref_languages.value = value
    }

var specialBackupsEnabled: Boolean
    get() = pref_enableSpecialBackups.value
    set(value) {
        pref_enableSpecialBackups.value = value
    }

fun Context.getLocaleOfCode(localeCode: String): Locale = when {
    localeCode.isEmpty()      -> resources.configuration.locales[0]
    localeCode.contains("-r") -> Locale(
        localeCode.substring(0, 2),
        localeCode.substring(4)
    )

    localeCode.contains("_")  -> Locale(
        localeCode.substring(0, 2),
        localeCode.substring(3)
    )

    else                      -> Locale(localeCode)
}

fun Context.getLanguageList() =
    mapOf(PREFS_LANGUAGES_SYSTEM to resources.getString(R.string.prefs_language_system)) +
            BuildConfig.DETECTED_LOCALES
                .sorted()
                .associateWith { translateLocale(getLocaleOfCode(it)) }

private fun translateLocale(locale: Locale): String {
    val country = locale.getDisplayCountry(locale)
    val language = locale.getDisplayLanguage(locale)
    return (language.replaceFirstChar { it.uppercase(Locale.getDefault()) }
            + (if (country.isNotEmpty() && country.compareTo(language, true) != 0)
        "($country)" else ""))
}

