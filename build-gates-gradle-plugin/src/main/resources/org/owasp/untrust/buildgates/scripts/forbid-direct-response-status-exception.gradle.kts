/*
 * SECURITY BUILD GATE: DIRECT RESPONSESTATUSEXCEPTION THROW ENFORCEMENT
 *
 * Application code must throw domain-relevant exceptions and let a central @ControllerAdvice
 * translate them to HTTP responses. This keeps logging centralized and keeps exception arguments
 * typed as domain values instead of raw primitives.
 *
 * This gate forbids throwing org.springframework.web.server.ResponseStatusException directly
 * outside @ControllerAdvice classes.
 */

import com.sun.source.tree.AnnotationTree
import com.sun.source.tree.ClassTree
import com.sun.source.tree.CompilationUnitTree
import com.sun.source.tree.ThrowTree
import com.sun.source.util.JavacTask
import com.sun.source.util.TreePath
import com.sun.source.util.TreePathScanner
import com.sun.source.util.Trees
import org.gradle.api.GradleException
import org.gradle.api.plugins.JavaPluginExtension
import org.gradle.api.tasks.SourceSet
import java.io.File
import java.io.StringWriter
import java.util.Locale
import javax.lang.model.type.TypeKind
import javax.lang.model.type.TypeMirror
import javax.lang.model.util.Elements
import javax.lang.model.util.Types
import javax.tools.Diagnostic
import javax.tools.DiagnosticCollector
import javax.tools.JavaFileObject
import javax.tools.ToolProvider

data class DirectResponseStatusExceptionFinding(
    val sourcePath: String,
    val lineNumber: Long
)

fun File.relativeUnixPath(rootDir: File): String {
    return rootDir.toPath()
        .relativize(toPath())
        .toString()
        .replace(File.separatorChar, '/')
}

fun sourceLine(compilationUnit: CompilationUnitTree, node: ThrowTree, trees: Trees): Long {
    val startPosition = trees.sourcePositions.getStartPosition(compilationUnit, node)

    return if (startPosition >= 0) {
        compilationUnit.lineMap.getLineNumber(startPosition)
    } else {
        -1L
    }
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

fun isConcreteReference(typeMirror: TypeMirror?): Boolean {
    return typeMirror != null &&
        typeMirror.kind != TypeKind.ERROR &&
        typeMirror.kind != TypeKind.NULL &&
        typeMirror.kind != TypeKind.NONE &&
        typeMirror.kind != TypeKind.VOID
}

fun isResponseStatusException(
    typeMirror: TypeMirror?,
    elements: Elements,
    types: Types
): Boolean {
    if (!isConcreteReference(typeMirror)) {
        return false
    }

    val responseStatusExceptionElement = elements.getTypeElement("org.springframework.web.server.ResponseStatusException")
        ?: return false

    return types.isAssignable(
        types.erasure(typeMirror),
        types.erasure(responseStatusExceptionElement.asType())
    )
}

fun isControllerAdviceAnnotation(annotation: AnnotationTree): Boolean {
    val annotationType = annotation.annotationType.toString()
    return annotationType == "ControllerAdvice" ||
        annotationType == "RestControllerAdvice" ||
        annotationType == "org.springframework.web.bind.annotation.ControllerAdvice" ||
        annotationType == "org.springframework.web.bind.annotation.RestControllerAdvice"
}

fun collectDirectResponseStatusExceptionThrows(
    compilationUnit: CompilationUnitTree,
    trees: Trees,
    elements: Elements,
    types: Types,
    rootDir: File
): List<DirectResponseStatusExceptionFinding> {
    val sourceFile = File(compilationUnit.sourceFile.toUri())
    val sourcePath = sourceFile.relativeUnixPath(rootDir)
    val findings = mutableListOf<DirectResponseStatusExceptionFinding>()
    val controllerAdviceDepth = mutableListOf<Boolean>()

    object : TreePathScanner<Unit, Unit>() {
        override fun visitClass(node: ClassTree, unused: Unit?) {
            val isControllerAdvice = node.modifiers.annotations.any(::isControllerAdviceAnnotation)
            controllerAdviceDepth += isControllerAdvice
            super.visitClass(node, unused)
            controllerAdviceDepth.removeLast()
        }

        override fun visitThrow(node: ThrowTree, unused: Unit?) {
            val insideControllerAdvice = controllerAdviceDepth.any { it }
            val thrownType = trees.getTypeMirror(TreePath(currentPath, node.expression))

            if (!insideControllerAdvice && isResponseStatusException(thrownType, elements, types)) {
                findings += DirectResponseStatusExceptionFinding(
                    sourcePath,
                    sourceLine(compilationUnit, node, trees)
                )
            }

            super.visitThrow(node, unused)
        }
    }.scan(compilationUnit, Unit)

    return findings
}

fun inspectSourceSetForDirectResponseStatusExceptionThrows(
    sourceSet: SourceSet,
    rootDir: File
): List<DirectResponseStatusExceptionFinding> {
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
        val elements = task.elements
        val types = task.types

        val errors = diagnostics.diagnostics
            .filter { it.kind == Diagnostic.Kind.ERROR }

        if (errors.isNotEmpty()) {
            val message = errors.joinToString("\n") { diagnostic ->
                val sourceName = diagnostic.source?.name ?: "<unknown source>"
                " - $sourceName:${diagnostic.lineNumber}: ${diagnostic.getMessage(Locale.ROOT)}"
            }

            throw GradleException("Failed to analyze Java source files before checking ResponseStatusException throws:\n$message")
        }

        return parsedUnits.flatMap { compilationUnit ->
            collectDirectResponseStatusExceptionThrows(compilationUnit, trees, elements, types, rootDir)
        }
    }
}

fun directResponseStatusExceptionFailureGuidance(): String {
    return """

DIRECT RESPONSESTATUSEXCEPTION POLICY FAILURE

Do not throw ResponseStatusException directly from controllers or services. Throw a domain-relevant
exception that carries validated value objects or other guarded domain types, then translate it in a
central @ControllerAdvice handler.

The central handler should log the domain exception with structured context and then produce the
appropriate HTTP response. This keeps server logs complete while avoiding primitive or unguarded PII
values in exception constructor arguments.
""".trimIndent()
}

val forbidDirectResponseStatusException by tasks.registering {
    group = "verification"
    description = "Fails the build when ResponseStatusException is thrown outside a central controller advice."

    val javaExtension = project.extensions.getByType<JavaPluginExtension>()
    val sourceSets = javaExtension.sourceSets

    sourceSets.configureEach {
        inputs.files(allJava)
        inputs.files(compileClasspath)
    }

    doLast {
        val findings = sourceSets.flatMap { sourceSet ->
            inspectSourceSetForDirectResponseStatusExceptionThrows(sourceSet, rootProject.projectDir)
        }

        if (findings.isNotEmpty()) {
            throw GradleException(
                "Direct ResponseStatusException throws found:\n" +
                    findings.sortedWith(compareBy({ it.sourcePath }, { it.lineNumber }))
                        .joinToString("\n") { " - ${it.sourcePath}:${it.lineNumber} throws ResponseStatusException directly." } +
                    "\n\n" +
                    directResponseStatusExceptionFailureGuidance()
            )
        }
    }
}

tasks.matching { it.name == "check" }.configureEach {
    dependsOn(forbidDirectResponseStatusException)
}
