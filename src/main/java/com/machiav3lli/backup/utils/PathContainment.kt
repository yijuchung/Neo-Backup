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

import java.io.File
import java.nio.file.Path
import java.nio.file.Paths

/**
 * SECURITY: purely lexical path-containment checks that defend the restore path against archive
 * path traversal ("tar slip" / "zip slip").
 *
 * A backup archive is untrusted input and is extracted as root, so an entry named `../../system/x`
 * or a symlink pointing outside the target directory could otherwise write anywhere on the device.
 * These checks are intentionally lexical (they never touch the filesystem), so they cannot be
 * fooled by — or accidentally follow — symlinks while running as root, and they run as fast local
 * JVM unit tests (see PathTraversalTest). They must run before any mkdir/write/link.
 */

/** True when [candidate] is the base itself or nested somewhere inside it. */
private fun Path.containsOrEquals(candidate: Path): Boolean =
    candidate == this || candidate.startsWith(this)

/**
 * Resolves [name] against [baseDir] and returns the resulting path only if it stays inside
 * [baseDir]. Absolute names and `../` escapes (including sibling-prefix tricks like `../pkgEVIL`)
 * return null.
 */
internal fun safeResolveInside(baseDir: File, name: String): File? = try {
    val base = Paths.get(baseDir.absolutePath).normalize()
    val resolved = base.resolve(name).normalize()
    if (base.containsOrEquals(resolved)) File(resolved.toString()) else null
} catch (_: Exception) {
    null
}

/**
 * Validates that a link entry's target ([linkName]), resolved relative to the link's own parent
 * directory, stays inside [baseDir]. Rejecting escaping link targets prevents the classic tar-slip
 * write-through: create a symlink pointing outside the target dir, then write a file through it as
 * root.
 */
internal fun isLinkTargetInside(baseDir: File, linkFile: File, linkName: String): Boolean = try {
    val base = Paths.get(baseDir.absolutePath).normalize()
    val parent = Paths.get(linkFile.absolutePath).normalize().parent ?: base
    val resolved = parent.resolve(linkName).normalize()
    base.containsOrEquals(resolved)
} catch (_: Exception) {
    false
}
