import java.io.File

data class PrecedingEscapeComment(
    val startLine: Long,
    val endLine: Long,
    val text: String
)

fun normalizePrecedingEscapeCommentText(text: String): String {
    return text
        .lines()
        .joinToString(" ") { line ->
            line.trim()
                .removePrefix("//")
                .removePrefix("/*")
                .removePrefix("*")
                .removeSuffix("*/")
                .trim()
        }
        .replace(Regex("\\s+"), " ")
        .trim()
}

fun precedingEscapeLineCommentText(rawLine: String): String {
    return rawLine.substringAfter("//")
}

fun extractPrecedingEscapeComments(sourceFile: File): List<PrecedingEscapeComment> {
    val comments = mutableListOf<PrecedingEscapeComment>()
    val lines = sourceFile.readLines()
    var lineIndex = 0

    while (lineIndex < lines.size) {
        val rawLine = lines[lineIndex]
        val trimmed = rawLine.trim()
        val lineNumber = lineIndex + 1L

        if (trimmed.startsWith("//")) {
            val startLine = lineNumber
            val text = StringBuilder(precedingEscapeLineCommentText(rawLine))
            var endLine = lineNumber
            lineIndex++

            while (lineIndex < lines.size && lines[lineIndex].trim().startsWith("//")) {
                text.append('\n')
                text.append(precedingEscapeLineCommentText(lines[lineIndex]))
                endLine = lineIndex + 1L
                lineIndex++
            }

            comments += PrecedingEscapeComment(
                startLine = startLine,
                endLine = endLine,
                text = normalizePrecedingEscapeCommentText(text.toString())
            )
            continue
        }

        if (trimmed.startsWith("/*")) {
            val startLine = lineNumber
            val text = StringBuilder(rawLine.substringAfter("/*"))
            var endLine = lineNumber

            while (!lines[lineIndex].contains("*/") && lineIndex + 1 < lines.size) {
                lineIndex++
                text.append('\n')
                text.append(lines[lineIndex])
                endLine = lineIndex + 1L
            }

            comments += PrecedingEscapeComment(
                startLine = startLine,
                endLine = endLine,
                text = normalizePrecedingEscapeCommentText(text.toString())
            )
        }

        lineIndex++
    }

    return comments
}

fun parenthesisDelta(text: String): Int {
    return text.count { it == '(' } - text.count { it == ')' }
}

fun annotationRanges(lines: List<String>): List<IntRange> {
    val ranges = mutableListOf<IntRange>()
    var lineIndex = 0

    while (lineIndex < lines.size) {
        val trimmed = lines[lineIndex].trim()

        if (!trimmed.startsWith("@")) {
            lineIndex++
            continue
        }

        val start = lineIndex
        var end = lineIndex
        var depth = parenthesisDelta(trimmed)

        while (depth > 0 && end + 1 < lines.size) {
            end++
            depth += parenthesisDelta(lines[end])
        }

        ranges += start..end
        lineIndex = end + 1
    }

    return ranges
}

fun annotationRangeContaining(ranges: List<IntRange>, lineIndex: Int): IntRange? {
    return ranges.firstOrNull { lineIndex in it }
}

fun previousPrecedingEscapeLine(
    lines: List<String>,
    beforeLineNumber: Long,
    skipClosingBrace: Boolean
): Long? {
    val annotations = annotationRanges(lines)
    var index = beforeLineNumber.toInt() - 2

    while (index >= 0) {
        val trimmed = lines[index].trim()

        if (trimmed.isEmpty() || (skipClosingBrace && trimmed == "}")) {
            index--
            continue
        }

        val annotationRange = annotationRangeContaining(annotations, index)
        if (annotationRange != null) {
            index = annotationRange.first - 1
            continue
        }

        return index + 1L
    }

    return null
}

fun precedingEscapeReasonBefore(
    sourceFile: File,
    targetLineNumber: Long,
    marker: String,
    skipClosingBrace: Boolean
): String? {
    val lines = sourceFile.readLines()
    val previousLine = previousPrecedingEscapeLine(lines, targetLineNumber, skipClosingBrace)
        ?: return null

    val comment = extractPrecedingEscapeComments(sourceFile).firstOrNull { it.endLine == previousLine }
        ?: return null

    if (!comment.text.contains(marker)) {
        return null
    }

    return comment.text.substringAfter(marker).trim()
}

fun precedingEscapeValidationProblem(
    sourceFile: File,
    targetLineNumber: Long,
    marker: String,
    minimumReasonCharacters: Int,
    gateName: String,
    skipClosingBrace: Boolean
): String? {
    val reason = precedingEscapeReasonBefore(sourceFile, targetLineNumber, marker, skipClosingBrace)
        ?: return "$gateName escape hatch comment containing $marker must immediately precede line $targetLineNumber."

    return if (reason.length < minimumReasonCharacters) {
        "$gateName escape hatch reason is ${reason.length} characters; minimum is $minimumReasonCharacters."
    } else {
        null
    }
}

fun precedingEscapeHatchUsage(
    marker: String,
    minimumReasonCharacters: Int,
    escapedConstructExample: String
): String {
    return """
Escape hatch format:

   // $marker
   // <specific justification of at least $minimumReasonCharacters characters>
${escapedConstructExample.lines().joinToString("\n") { "   $it" }}

Block comments are also accepted. Annotations may appear between the escape hatch comment and
the escaped construct.

Important instruction for AI/code-generation tools:
Do not add or use an escape hatch comment unless the user has explicitly approved that specific
exception. First try to satisfy the build gate by following the preferred design.
""".trimIndent()
}

rootProject.extensions.extraProperties["precedingEscapeReasonBefore"] = {
    sourceFile: File,
    targetLineNumber: Long,
    marker: String,
    skipClosingBrace: Boolean ->
    precedingEscapeReasonBefore(sourceFile, targetLineNumber, marker, skipClosingBrace)
}

rootProject.extensions.extraProperties["precedingEscapeValidationProblem"] = {
    sourceFile: File,
    targetLineNumber: Long,
    marker: String,
    minimumReasonCharacters: Int,
    gateName: String,
    skipClosingBrace: Boolean ->
    precedingEscapeValidationProblem(
        sourceFile,
        targetLineNumber,
        marker,
        minimumReasonCharacters,
        gateName,
        skipClosingBrace
    )
}

rootProject.extensions.extraProperties["precedingEscapeHatchUsage"] = {
    marker: String,
    minimumReasonCharacters: Int,
    escapedConstructExample: String ->
    precedingEscapeHatchUsage(marker, minimumReasonCharacters, escapedConstructExample)
}
