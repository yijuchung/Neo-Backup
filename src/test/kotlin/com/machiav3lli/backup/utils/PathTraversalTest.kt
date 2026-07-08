package com.machiav3lli.backup.utils

import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Unit tests for the archive path-traversal ("tar slip") defenses used by
 * [safeResolveInside] and [isLinkTargetInside] in TarUtils.
 *
 * These are pure, filesystem-free lexical checks, so they run as fast local JVM
 * unit tests. They guard the security-critical restore path that writes as root.
 */
class PathTraversalTest {

    private val base = File("/data/user/0/app/restore/pkg")

    // ---- safeResolveInside: entries that stay inside are allowed ----

    @Test
    fun allows_normal_file() {
        assertNotNull(safeResolveInside(base, "files/db.sqlite"))
    }

    @Test
    fun allows_nested_path() {
        assertNotNull(safeResolveInside(base, "a/b/c/d.txt"))
    }

    @Test
    fun allows_current_dir() {
        assertNotNull(safeResolveInside(base, "."))
    }

    @Test
    fun allows_embedded_dotdot_that_stays_inside() {
        assertNotNull(safeResolveInside(base, "a/b/../c"))
    }

    // ---- safeResolveInside: escaping entries are rejected (null) ----

    @Test
    fun rejects_parent_escape() {
        assertNull(safeResolveInside(base, "../evil"))
    }

    @Test
    fun rejects_deep_parent_escape() {
        assertNull(safeResolveInside(base, "../../../system/bin/x"))
    }

    @Test
    fun rejects_mid_path_escape() {
        assertNull(safeResolveInside(base, "a/../../etc/passwd"))
    }

    @Test
    fun rejects_absolute_path() {
        assertNull(safeResolveInside(base, "/etc/passwd"))
    }

    @Test
    fun rejects_absolute_system_path() {
        assertNull(safeResolveInside(base, "/data/system/packages.xml"))
    }

    @Test
    fun rejects_sibling_prefix_directory() {
        // Classic string-prefix bug: "pkgEVIL" starts with "pkg" but is a different dir.
        assertNull(safeResolveInside(base, "../pkgEVIL/x"))
    }

    // ---- isLinkTargetInside: link targets are validated ----

    @Test
    fun link_target_inside_is_allowed() {
        val link = File(base, "files/link")
        assertTrue(isLinkTargetInside(base, link, "../db/real.db"))
    }

    @Test
    fun link_target_same_dir_is_allowed() {
        val link = File(base, "files/link")
        assertTrue(isLinkTargetInside(base, link, "sibling"))
    }

    @Test
    fun link_target_relative_escape_is_rejected() {
        val link = File(base, "files/link")
        assertFalse(isLinkTargetInside(base, link, "../../../../system/x"))
    }

    @Test
    fun link_target_absolute_escape_is_rejected() {
        val link = File(base, "files/link")
        assertFalse(isLinkTargetInside(base, link, "/system/bin/sh"))
    }

    @Test
    fun link_target_into_other_app_is_rejected() {
        val link = File(base, "files/link")
        assertFalse(isLinkTargetInside(base, link, "/data/data/other/x"))
    }
}
