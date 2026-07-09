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
package com.machiav3lli.backup.manager.handler

import java.io.File

/**
 * SECURITY: pure, side-effect-free shell-argument quoting and command splitting for the root
 * shell (Android's shell is mksh).
 *
 * Any value that flows into a `runAsRoot(...)` command and is not fully controlled by this app
 * (package names, permissions, file paths read from backup metadata, ...) is a command-injection
 * risk. [quote] wraps such a value into a single inert, double-quoted shell token so the shell
 * cannot re-interpret it as extra words or commands.
 *
 * mksh double-quote rules (from the mksh man page): inside `"..."` every character is literal
 * except `$`, `` ` `` and `\`, so escaping exactly those three plus the closing `"` is both
 * necessary and sufficient. Kept deliberately free of Android dependencies so it can be unit
 * tested on the plain JVM (see ShellQuotingTest).
 */
object ShellQuoting {

    // Only these characters keep a special meaning inside mksh double quotes, so only these
    // need a backslash escape (blacklist, not whitelist, to stay lossless for every input).
    private val charactersToBeEscaped = Regex("""[\\${'$'}"`]""")

    /** Wraps [parameter] into a single, fully escaped mksh double-quoted token. */
    fun quote(parameter: String): String =
        "\"${parameter.replace(charactersToBeEscaped) { "\\${it.value}" }}\""

    /** Convenience overload that quotes a file's absolute path. */
    fun quote(parameter: File): String = quote(parameter.absolutePath)

    /** Quotes every element of [parameters] and joins them with spaces into a command fragment. */
    fun quoteMultiple(parameters: Collection<String>): String =
        parameters.joinToString(" ", transform = ::quote)

    /**
     * Splits a shell [command] line into its argument tokens, honouring single quotes, double
     * quotes and backslash escapes inside double quotes. This is the inverse used to reason
     * about (and test) what [quote] emits, and to feed `Runtime.exec` an argv array.
     */
    fun splitCommand(command: String): List<String> {
        val result = mutableListOf<String>()
        var current = StringBuilder()
        var inDoubleQuotes = false
        var inSingleQuotes = false
        var escapeNext = false

        for (char in command) {
            when {
                escapeNext          -> {
                    current.append(char)
                    escapeNext = false
                }

                char == '\\'        -> {
                    if (inDoubleQuotes) {
                        escapeNext = true
                    } else {
                        current.append(char)
                    }
                }

                char == '"'         -> {
                    if (inSingleQuotes) {
                        current.append(char)
                    } else {
                        inDoubleQuotes = !inDoubleQuotes
                        if (!inDoubleQuotes) {
                            result.add(current.toString())
                            current = StringBuilder()
                        }
                    }
                }

                char == '\''        -> {
                    if (inDoubleQuotes) {
                        current.append(char)
                    } else {
                        inSingleQuotes = !inSingleQuotes
                        if (!inSingleQuotes) {
                            result.add(current.toString())
                            current = StringBuilder()
                        }
                    }
                }

                char.isWhitespace() -> {
                    if (inDoubleQuotes || inSingleQuotes) {
                        current.append(char)
                    } else if (current.isNotEmpty()) {
                        result.add(current.toString())
                        current = StringBuilder()
                    }
                }

                else                -> {
                    current.append(char)
                }
            }
        }

        if (current.isNotEmpty()) {
            result.add(current.toString())
        }

        return result
    }
}
