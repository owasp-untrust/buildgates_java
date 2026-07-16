/*
 * DESIGN BUILD GATE: PUBLIC VALUE ON SENSITIVE TYPES
 *
 * PII types and self-validating types must not also be PublicValue types.
 * PublicValue makes value exposure part of the type contract. For PII that defeats value hiding,
 * and for self-validating values it makes it easy to consume the partially exposed value while
 * forgetting the contextual validation boundary.
 */

import com.sun.source.tree.ClassTree
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
import javax.lang.model.element.TypeElement
import javax.lang.model.type.DeclaredType
import javax.lang.model.type.TypeMirror
import javax.lang.model.util.Types
import javax.tools.Diagnostic
import javax.tools.DiagnosticCollector
import javax.tools.JavaFileObject
import javax.tools.ToolProvider

val PUBLIC_VALUE_TYPE = "org.owasp.untrust.vv.PublicValue"
val PII_TYPE = "org.owasp.untrust.vv.Pii"
val CROSS_SELF_VALIDATING_TYPE = "org.owasp.untrust.vv.CrossSelfValidating"
val CANDIDATE_MARKER_TYPE = "org.owasp.untrust.vv.CrossSelfValidating.CandidateMarker"

data class SensitivePublicValueFinding(
    val sourcePath: String,
    val lineNumber: Long,
    val typeName: String,
    val sensitiveTypeName: String
)

fun File.relativeUnixPath(rootDir: File): String {
    return rootDir.toPath()
        .relativize(toPath())
        .toString()
        .replace(File.separatorChar, '/')
}

fun sourceLine(compilationUnit: CompilationUnitTree, tree: ClassTree, trees: Trees): Long {
    val startPosition = trees.sourcePositions.getStartPosition(compilationUnit, tree)

    return if (startPosition >= 0) {
        compilationUnit.lineMap.getLineNumber(startPosition)
    } else {
        -1L
    }
}

fun TypeMirror.qualifiedTypeName(): String? {
    return (this as? DeclaredType)
        ?.asElement()
        ?.let { it as? TypeElement }
        ?.qualifiedName
        ?.toString()
}

fun allSupertypeNames(type: TypeMirror, types: Types): Set<String> {
    val visited = mutableSetOf<String>()

    fun visit(current: TypeMirror) {
        val name = current.qualifiedTypeName()

        if (name != null && !visited.add(name)) {
            return
        }

        types.directSupertypes(current).forEach(::visit)
    }

    visit(type)
    return visited
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

fun inspectSourceSetForSensitivePublicValues(
    sourceSet: SourceSet,
    rootDir: File
): List<SensitivePublicValueFinding> {
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
        task.analyze()

        val errors = diagnostics.diagnostics
            .filter { it.kind == Diagnostic.Kind.ERROR }

        if (errors.isNotEmpty()) {
            val message = errors.joinToString("\n") { diagnostic ->
                val sourceName = diagnostic.source?.name ?: "<unknown source>"
                " - $sourceName:${diagnostic.lineNumber}: ${diagnostic.getMessage(Locale.ROOT)}"
            }

            throw GradleException("Failed to analyze Java source files before checking sensitive PublicValue types:\n$message")
        }

        return parsedUnits.flatMap { compilationUnit ->
            val sourceFile = File(compilationUnit.sourceFile.toUri())
            val sourcePath = sourceFile.relativeUnixPath(rootDir)
            val findings = mutableListOf<SensitivePublicValueFinding>()

            object : TreePathScanner<Unit, Unit>() {
                override fun visitClass(node: ClassTree, unused: Unit?) {
                    val element = trees.getElement(currentPath) as? TypeElement

                    if (element != null) {
                        val supertypeNames = allSupertypeNames(element.asType(), task.types)

                        if (PUBLIC_VALUE_TYPE in supertypeNames) {
                            val sensitiveTypeName = listOf(PII_TYPE, CROSS_SELF_VALIDATING_TYPE, CANDIDATE_MARKER_TYPE)
                                .firstOrNull { it in supertypeNames }

                            if (sensitiveTypeName != null) {
                                findings += SensitivePublicValueFinding(
                                    sourcePath = sourcePath,
                                    lineNumber = sourceLine(compilationUnit, node, trees),
                                    typeName = element.qualifiedName.toString(),
                                    sensitiveTypeName = sensitiveTypeName
                                )
                            }
                        }
                    }

                    super.visitClass(node, unused)
                }
            }.scan(compilationUnit, Unit)

            findings
        }
    }
}

val forbidPublicValueOnSensitiveTypes by tasks.registering {
    group = "verification"
    description = "Fails the build when PII or self-validating types also implement PublicValue."

    val javaExtension = project.extensions.getByType<JavaPluginExtension>()
    val sourceSets = javaExtension.sourceSets

    sourceSets.configureEach {
        inputs.files(allJava)
        inputs.files(compileClasspath)
    }

    doLast {
        val findings = sourceSets.flatMap { sourceSet ->
            inspectSourceSetForSensitivePublicValues(sourceSet, rootProject.projectDir)
        }

        if (findings.isNotEmpty()) {
            throw GradleException(
                "Sensitive types must not be PublicValue types:\n" +
                    findings.joinToString("\n") { finding ->
                        " - ${finding.sourcePath}:${finding.lineNumber} ${finding.typeName} combines PublicValue with ${finding.sensitiveTypeName}."
                    } +
                    "\n\nPII values must keep hiding behavior explicit, and self-validating values must not expose a public-value contract that can bypass contextual validation assurance."
            )
        }
    }
}

tasks.matching { it.name == "check" }.configureEach {
    dependsOn(forbidPublicValueOnSensitiveTypes)
}
