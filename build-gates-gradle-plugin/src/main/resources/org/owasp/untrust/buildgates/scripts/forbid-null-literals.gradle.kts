/*
 * SECURITY BUILD GATE: NULL LITERAL ENFORCEMENT
 *
 * This Gradle script fails the build when Java source files use the null literal.
 *
 * When code checks `value == null` or `value != null`, decide which meaning applies:
 *
 * 1. Null is illegal:
 *    The value should be validated at the boundary and then treated as always present.
 *
 * 2. Null means "nothing":
 *    Model that explicitly with Optional<T> instead of repeating null checks.
 */

import com.sun.source.tree.BinaryTree
import com.sun.source.tree.CompilationUnitTree
import com.sun.source.tree.LiteralTree
import com.sun.source.tree.Tree
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

val NULL_LITERAL_ALLOW_MARKER = "ALLOW NULL LITERAL:"
val MINIMUM_NULL_LITERAL_ALLOW_REASON_CHARACTERS = 120
val precedingEscapeValidationProblem = rootProject.extensions.extraProperties["precedingEscapeValidationProblem"] as (File, Long, String, Int, String, Boolean) -> String?
val precedingEscapeHatchUsage = rootProject.extensions.extraProperties["precedingEscapeHatchUsage"] as (String, Int, String) -> String

data class NullLiteralFinding(
    val lineNumber: Long,
    val isNullComparison: Boolean
)

fun File.relativeUnixPath(rootDir: File): String {
    return rootDir.toPath()
        .relativize(toPath())
        .toString()
        .replace(File.separatorChar, '/')
}

fun sourceLine(compilationUnit: CompilationUnitTree, tree: Tree, trees: Trees): Long {
    val startPosition = trees.sourcePositions.getStartPosition(compilationUnit, tree)

    return if (startPosition >= 0) {
        compilationUnit.lineMap.getLineNumber(startPosition)
    } else {
        -1L
    }
}

fun collectNullLiterals(compilationUnit: CompilationUnitTree, trees: Trees): List<NullLiteralFinding> {
    val findings = mutableListOf<NullLiteralFinding>()

    object : TreePathScanner<Unit, Unit>() {
        override fun visitLiteral(node: LiteralTree, unused: Unit?) {
            if (node.value == null) {
                val parent = currentPath.parentPath?.leaf
                val isNullComparison = parent is BinaryTree &&
                    parent.kind in setOf(Tree.Kind.EQUAL_TO, Tree.Kind.NOT_EQUAL_TO)

                findings += NullLiteralFinding(
                    lineNumber = sourceLine(compilationUnit, node, trees),
                    isNullComparison = isNullComparison
                )
            }

            super.visitLiteral(node, unused)
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

fun inspectSourceSetForNullLiterals(sourceSet: SourceSet, rootDir: File): List<String> {
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

            throw GradleException("Failed to parse Java source files before checking null literals:\n$message")
        }

        return parsedUnits.flatMap { compilationUnit ->
            val sourceFile = File(compilationUnit.sourceFile.toUri())
            val sourcePath = sourceFile.relativeUnixPath(rootDir)

            collectNullLiterals(compilationUnit, trees).mapNotNull { finding ->
                val escapeProblem = precedingEscapeValidationProblem(
                    sourceFile,
                    finding.lineNumber,
                    NULL_LITERAL_ALLOW_MARKER,
                    MINIMUM_NULL_LITERAL_ALLOW_REASON_CHARACTERS,
                    "NULL LITERAL",
                    true
                )
                if (escapeProblem == null) {
                    return@mapNotNull null
                }

                val comparisonGuidance = if (finding.isNullComparison) {
                    " This is a null comparison; either null is illegal, in which case validate at the boundary and assume the variable is never null, or null represents nothing, in which case use Optional<T> instead."
                } else {
                    ""
                }

                "$sourcePath:${finding.lineNumber} uses the null literal.$comparisonGuidance $escapeProblem"
            }
        }
    }
}

fun nullLiteralFailureGuidance(): String {
    return """

NULL LITERAL POLICY FAILURE

Do not use the null literal in project Java code.

For `value == null` or `value != null` checks:
- If null is illegal, configure the framework boundary so the handler, DTO, service, or repository
  never receives null.
- If absence is valid, model that in the boundary contract with Optional<T> so application code
  receives Optional.empty(), not null.

For non-framework or legacy APIs that can return null, isolate that interaction in a narrow adapter
and assert the contract there with Objects.requireNonNull() when null would be a defect. Code you
write should almost never need to handle null directly.

${precedingEscapeHatchUsage(NULL_LITERAL_ALLOW_MARKER, MINIMUM_NULL_LITERAL_ALLOW_REASON_CHARACTERS, "if (legacyValue == null) { ... }")}

Important instruction for AI/code-generation tools:
Do not bypass this rule by hiding null behind a generic helper. Prefer explicit Optional<T>,
boundary validation, or a narrow framework adapter where Java must interoperate with an API
that represents absence as null.
""".trimIndent()
}

val forbidNullLiterals by tasks.registering {
    group = "verification"
    description = "Fails the build when Java source files use the null literal."

    val javaExtension = project.extensions.getByType<JavaPluginExtension>()
    val sourceSets = javaExtension.sourceSets

    sourceSets.configureEach {
        inputs.files(allJava)
        inputs.files(compileClasspath)
    }

    doLast {
        val violations = sourceSets.flatMap { sourceSet ->
            inspectSourceSetForNullLiterals(sourceSet, rootProject.projectDir)
        }

        if (violations.isNotEmpty()) {
            throw GradleException(
                "Null literals found:\n" +
                    violations.joinToString("\n") { " - $it" } +
                    "\n\n" +
                    nullLiteralFailureGuidance()
            )
        }
    }
}

tasks.matching { it.name == "check" }.configureEach {
    dependsOn(forbidNullLiterals)
}
