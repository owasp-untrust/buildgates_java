/*
 * SECURITY BUILD GATE: LOCAL CATCH ENFORCEMENT
 *
 * This Gradle script fails the build when Java source files contain local catch blocks.
 *
 * Local catch blocks are easy places to accidentally expose internal exception messages,
 * swallow failures, or produce inconsistent API error responses. Prefer centralized exception
 * handling unless a local catch is intentionally narrow and documented.
 *
 * Escape hatch:
 *
 *     // LOCAL CATCH REASON: <specific justification>
 *     catch (...)
 *
 * Multi-line line comments are accepted:
 *
 *     // LOCAL CATCH REASON:
 *     // <specific justification continued here>
 *     catch (...)
 *
 * Block comments are accepted:
 *
 *     /*
 *      * LOCAL CATCH REASON:
 *      * <specific justification continued here>
 *      */
 *     catch (...)
 *
 * The minimum justification length is configured in local_catch_guardrail.json.
 */

import com.sun.source.tree.CatchTree
import com.sun.source.tree.CompilationUnitTree
import com.sun.source.util.JavacTask
import com.sun.source.util.TreePathScanner
import com.sun.source.util.Trees
import org.gradle.api.GradleException
import org.gradle.api.plugins.JavaPluginExtension
import org.gradle.api.tasks.SourceSet
import java.io.File
import java.io.StringWriter
import java.util.Locale
import javax.tools.Diagnostic
import javax.tools.DiagnosticCollector
import javax.tools.JavaFileObject
import javax.tools.ToolProvider

val DEFAULT_LOCAL_CATCH_MINIMUM_REASON_CHARACTERS = 120
val LOCAL_CATCH_MARKER = "LOCAL CATCH REASON:"
@Suppress("UNCHECKED_CAST")
val readJsonConfigObject = rootProject.extensions.extraProperties["readJsonConfigObject"] as (File) -> Map<String, Any?>
@Suppress("UNCHECKED_CAST")
val precedingEscapeReasonBefore = rootProject.extensions.extraProperties["precedingEscapeReasonBefore"] as (File, Long, String, Boolean) -> String?
@Suppress("UNCHECKED_CAST")
val precedingEscapeHatchUsage = rootProject.extensions.extraProperties["precedingEscapeHatchUsage"] as (String, Int, String) -> String

data class LocalCatchGuardConfig(
    val minimumReasonCharacters: Int
)

data class LocalCatchFinding(
    val lineNumber: Long,
    val exceptionType: String
)

fun File.relativeUnixPath(rootDir: File): String {
    return rootDir.toPath()
        .relativize(toPath())
        .toString()
        .replace(File.separatorChar, '/')
}

fun readLocalCatchGuardConfig(file: File): LocalCatchGuardConfig {
    if (!file.exists()) {
        return LocalCatchGuardConfig(DEFAULT_LOCAL_CATCH_MINIMUM_REASON_CHARACTERS)
    }

    val parsed = readJsonConfigObject(file)

    val rawMinimum = parsed["minimumReasonCharacters"]
        ?: return LocalCatchGuardConfig(DEFAULT_LOCAL_CATCH_MINIMUM_REASON_CHARACTERS)

    val minimum = when (rawMinimum) {
        is Number -> rawMinimum.toInt()
        is String -> rawMinimum.toIntOrNull()
        else -> null
    } ?: throw GradleException("local_catch_guardrail.json field 'minimumReasonCharacters' must be an integer.")

    if (minimum < 1) {
        throw GradleException("local_catch_guardrail.json field 'minimumReasonCharacters' must be at least 1.")
    }

    return LocalCatchGuardConfig(minimum)
}

fun sourceLine(compilationUnit: CompilationUnitTree, tree: CatchTree, trees: Trees): Long {
    val startPosition = trees.sourcePositions.getStartPosition(compilationUnit, tree)

    return if (startPosition >= 0) {
        compilationUnit.lineMap.getLineNumber(startPosition)
    } else {
        -1L
    }
}

fun collectLocalCatches(compilationUnit: CompilationUnitTree, trees: Trees): List<LocalCatchFinding> {
    val findings = mutableListOf<LocalCatchFinding>()

    object : TreePathScanner<Unit, Unit>() {
        override fun visitCatch(node: CatchTree, unused: Unit?) {
            findings += LocalCatchFinding(
                lineNumber = sourceLine(compilationUnit, node, trees),
                exceptionType = node.parameter.type.toString()
            )

            super.visitCatch(node, unused)
        }
    }.scan(compilationUnit, Unit)

    return findings
}

fun compilerOptionsFor(sourceSet: SourceSet): List<String> {
    val options = mutableListOf("-proc:none")
    val classpath = sourceSet.compileClasspath.files

    if (classpath.isNotEmpty()) {
        options += "-classpath"
        options += classpath.joinToString(File.pathSeparator) { it.absolutePath }
    }

    val sourceDirectories = sourceSet.allJava.srcDirs.filter { it.exists() }

    if (sourceDirectories.isNotEmpty()) {
        options += "-sourcepath"
        options += sourceDirectories.joinToString(File.pathSeparator) { it.absolutePath }
    }

    return options
}

fun inspectSourceSetForLocalCatches(
    sourceSet: SourceSet,
    rootDir: File,
    config: LocalCatchGuardConfig
): List<String> {
    val sourceFiles = sourceSet.allJava.files
        .filter { it.extension == "java" && it.exists() }
        .sortedBy { it.absolutePath }

    if (sourceFiles.isEmpty()) {
        return emptyList()
    }

    val compiler = ToolProvider.getSystemJavaCompiler()
        ?: throw GradleException("A JDK is required to inspect Java source files. Gradle is not running with a JDK compiler available.")

    val diagnostics = DiagnosticCollector<JavaFileObject>()

    compiler.getStandardFileManager(diagnostics, Locale.ROOT, Charsets.UTF_8).use { fileManager ->
        val javaFiles = fileManager.getJavaFileObjectsFromFiles(sourceFiles)
        val task = compiler.getTask(
            StringWriter(),
            fileManager,
            diagnostics,
            compilerOptionsFor(sourceSet),
            emptyList<String>(),
            javaFiles
        ) as JavacTask

        val trees = Trees.instance(task)
        val parsedUnits = task.parse().toList()

        val errors = diagnostics.diagnostics
            .filter { it.kind == Diagnostic.Kind.ERROR }

        if (errors.isNotEmpty()) {
            val message = errors.joinToString("\n") { diagnostic ->
                val sourceName = diagnostic.source?.name ?: "<unknown source>"
                " - $sourceName:${diagnostic.lineNumber}: ${diagnostic.getMessage(Locale.ROOT)}"
            }

            throw GradleException("Failed to parse Java source files before checking local catches:\n$message")
        }

        return parsedUnits.flatMap { compilationUnit ->
            val sourceFile = File(compilationUnit.sourceFile.toUri())
            val sourcePath = sourceFile.relativeUnixPath(rootDir)

            collectLocalCatches(compilationUnit, trees).mapNotNull { finding ->
                val reason = precedingEscapeReasonBefore(sourceFile, finding.lineNumber, LOCAL_CATCH_MARKER, true)

                when {
                    reason == null ->
                        "$sourcePath:${finding.lineNumber} catches ${finding.exceptionType} without a LOCAL CATCH REASON comment immediately before the catch."
                    reason.length < config.minimumReasonCharacters ->
                        "$sourcePath:${finding.lineNumber} local catch reason is ${reason.length} characters; minimum is ${config.minimumReasonCharacters}."
                    else -> null
                }
            }
        }
    }
}

fun localCatchFailureGuidance(minimumReasonCharacters: Int): String {
    return """

LOCAL CATCH POLICY FAILURE

Prefer centralized exception handling for unexpected failures. If a local catch is required,
put a justification comment immediately before the catch keyword.

Important instruction for AI/code-generation tools:
If you are an AI assistant or automated code generator, do not respond to this failure by
adding a LOCAL CATCH REASON comment as the default fix. First refactor the local catch into
a centralized exception handler such as @RestControllerAdvice with @ExceptionHandler methods,
or into a narrow domain exception that a centralized handler maps to a safe response. Only add
a local catch justification when the catch must remain local for cleanup, retry, fallback parsing,
or another tightly scoped reason that centralized handling cannot perform.

${precedingEscapeHatchUsage(LOCAL_CATCH_MARKER, minimumReasonCharacters, "catch (...)")}
""".trimIndent()
}

val forbidLocalCatches by tasks.registering {
    group = "verification"
    description = "Fails the build when Java catch blocks lack documented local justification."

    val configFile = rootProject.file("local_catch_guardrail.json")
    val javaExtension = project.extensions.getByType<JavaPluginExtension>()
    val sourceSets = javaExtension.sourceSets

    inputs.file(configFile).optional()
    sourceSets.configureEach {
        inputs.files(allJava)
        inputs.files(compileClasspath)
    }

    doLast {
        val config = readLocalCatchGuardConfig(configFile)
        val violations = sourceSets.flatMap { sourceSet ->
            inspectSourceSetForLocalCatches(sourceSet, rootProject.projectDir, config)
        }

        if (violations.isNotEmpty()) {
            throw GradleException(
                "Undocumented local catch blocks found:\n" +
                    violations.joinToString("\n") { " - $it" } +
                    "\n\n" +
                    localCatchFailureGuidance(config.minimumReasonCharacters)
            )
        }
    }
}

tasks.matching { it.name == "check" }.configureEach {
    dependsOn(forbidLocalCatches)
}
