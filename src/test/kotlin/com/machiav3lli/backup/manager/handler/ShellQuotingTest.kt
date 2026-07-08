package com.machiav3lli.backup.manager.handler

import com.machiav3lli.backup.manager.handler.ShellHandler.Companion.quote
import com.machiav3lli.backup.manager.handler.ShellHandler.Companion.splitCommand
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Unit tests for the shell-argument quoting ([quote]) and command splitting
 * ([splitCommand]) used to build root shell commands. Un-quoted parameters here
 * are a command-injection risk (see the F3 audit finding), so these tests pin the
 * escaping behaviour against injection payloads.
 */
class ShellQuotingTest {

    /**
     * Independent model of how a POSIX/mksh shell interprets a double-quoted word:
     * a backslash escapes the following character, everything else is literal.
     * Used to prove [quote] is lossless and fully wraps its argument, without
     * re-using quote()'s own implementation.
     */
    private fun shellUnquote(quoted: String): String {
        assertTrue("must be wrapped in double quotes", quoted.length >= 2)
        assertEquals('"', quoted.first())
        assertEquals('"', quoted.last())
        val inner = quoted.substring(1, quoted.length - 1)
        val sb = StringBuilder()
        var i = 0
        while (i < inner.length) {
            val c = inner[i]
            if (c == '\\' && i + 1 < inner.length) {
                sb.append(inner[i + 1]); i += 2
            } else {
                sb.append(c); i++
            }
        }
        return sb.toString()
    }

    /** Inner content must contain no UNescaped shell-active metacharacter. */
    private fun assertNoUnescapedMetachars(quoted: String) {
        val inner = quoted.substring(1, quoted.length - 1)
        var i = 0
        while (i < inner.length) {
            val c = inner[i]
            if (c == '\\') {
                i += 2 // skip the escaped char
                continue
            }
            assertFalse("unescaped '$' would allow expansion in: $quoted", c == '$')
            assertFalse("unescaped backtick would allow substitution in: $quoted", c == '`')
            assertFalse("unescaped double quote would break out in: $quoted", c == '"')
            i++
        }
    }

    private val payloads = listOf(
        "com.example.app",
        "a b c",
        "a;b|c&d",
        "\$HOME",
        "\$(id)",
        "`id`",
        "a\"b",
        "a\\b",
        "a'b",
        "*.?[abc]",
        "x\ny",
        "x\$(touch /tmp/pwned)y",
        "x`touch /tmp/pwned`y",
        "x\";touch /tmp/pwned;\"y",
        "",
    )

    @Test
    fun quote_is_lossless_and_fully_wraps_argument() {
        for (p in payloads) {
            assertEquals("round trip failed for [$p]", p, shellUnquote(quote(p)))
        }
    }

    @Test
    fun quote_neutralizes_injection_metacharacters() {
        for (p in payloads) {
            assertNoUnescapedMetachars(quote(p))
        }
    }

    @Test
    fun quote_escapes_each_special_character() {
        assertEquals("\"\\\$HOME\"", quote("\$HOME"))
        assertEquals("\"a\\\"b\"", quote("a\"b"))
        assertEquals("\"a\\\\b\"", quote("a\\b"))
    }

    @Test
    fun quote_leaves_plain_text_intact_but_wrapped() {
        assertEquals("\"com.example.app\"", quote("com.example.app"))
    }

    /**
     * Regression for the F3 remediation: a package name / permission read from an
     * untrusted backup .properties file flows unescaped into `runAsRoot("pm ... $pkg")`
     * style commands (RestoreAppAction, AppPage). Building such a command with quote()
     * applied to a malicious value must keep the payload as a single inert token that
     * the shell cannot re-interpret as extra commands.
     */
    @Test
    fun quotedCommand_containsInjectionFromUntrustedPackageName() {
        val maliciousPkg = "x\$(reboot)`id`;rm -rf /"
        val perm = "android.permission.CAMERA;wipe"

        // Same shape as the real "pm grant --user 0 <pkg> <perm>" sink.
        val cmd = "pm grant --user 0 ${quote(maliciousPkg)} ${quote(perm)}"
        val tokens = splitCommand(cmd)

        // The whole package payload survives as exactly one argument (token index 4),
        // i.e. it was NOT split into extra shell words/commands.
        assertEquals(listOf("pm", "grant", "--user", "0", maliciousPkg, perm), tokens)

        // And nothing in the emitted command exposes an unescaped expansion metachar.
        assertNoUnescapedMetachars(quote(maliciousPkg))
        assertNoUnescapedMetachars(quote(perm))
    }

    // ---- splitCommand ----

    @Test
    fun split_plain_command() {
        assertEquals(listOf("pm", "install", "x"), splitCommand("pm install x"))
    }

    @Test
    fun split_collapses_whitespace() {
        assertEquals(listOf("a", "b", "c"), splitCommand("a  b\tc"))
    }

    @Test
    fun split_double_quoted_group() {
        assertEquals(listOf("hello world"), splitCommand("\"hello world\""))
    }

    @Test
    fun split_single_quoted_group() {
        assertEquals(listOf("single quoted"), splitCommand("'single quoted'"))
    }

    @Test
    fun split_empty_command_is_empty_list() {
        assertEquals(emptyList<String>(), splitCommand(""))
        assertEquals(emptyList<String>(), splitCommand("   "))
    }
}
