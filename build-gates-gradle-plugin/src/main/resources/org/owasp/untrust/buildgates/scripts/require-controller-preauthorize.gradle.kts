/*
 * SECURITY BUILD GATE: CONTROLLER PREAUTHORIZE ENFORCEMENT
 *
 * Every Spring controller must have a class-level @PreAuthorize("denyAll()")
 * and every route method must have its own @PreAuthorize expression.
 *
 * The only class-level exception is an admin-only controller annotated with
 * @PreAuthorize("hasRole('ADMIN')"). In that case the whole controller is already
 * intentionally scoped to administrators.
 */

import com.sun.source.tree.AnnotationTree
import com.sun.source.tree.ClassTree
import com.sun.source.tree.CompilationUnitTree
import com.sun.source.tree.MethodTree
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

data class ControllerPreAuthorizeFinding(
    val sourcePath: String,
    val lineNumber: Long,
    val message: String
)

fun File.controllerPreAuthorizeRelativeUnixPath(rootDir: File): String {
    return rootDir.toPath()
        .relativize(toPath())
        .toString()
        .replace(File.separatorChar, '/')
}

fun controllerPreAuthorizeCompilerOptionsFor(sourceSet: SourceSet): List<String> {
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

fun controllerPreAuthorizeSimpleAnnotationName(annotation: AnnotationTree): String {
    return annotation.annotationType.toString().substringAfterLast('.')
}

fun hasControllerAnnotation(node: ClassTree): Boolean {
    return node.modifiers.annotations.any { annotation ->
        val annotationName = controllerPreAuthorizeSimpleAnnotationName(annotation)
        annotationName == "Controller" || annotationName == "RestController"
    }
}

fun hasRouteAnnotation(node: MethodTree): Boolean {
    return node.modifiers.annotations.any { annotation ->
        when (controllerPreAuthorizeSimpleAnnotationName(annotation)) {
            "RequestMapping",
            "GetMapping",
            "PostMapping",
            "PutMapping",
            "DeleteMapping",
            "PatchMapping" -> true
            else -> false
        }
    }
}

fun preAuthorizeValue(annotation: AnnotationTree): String? {
    if (controllerPreAuthorizeSimpleAnnotationName(annotation) != "PreAuthorize") {
        return null
    }

    val annotationText = annotation.toString()
    val start = annotationText.indexOf('"')
    val end = annotationText.lastIndexOf('"')

    return if (start >= 0 && end > start) {
        annotationText.substring(start + 1, end)
    } else {
        null
    }
}

fun preAuthorizeValues(annotations: List<AnnotationTree>): List<String> {
    return annotations.mapNotNull(::preAuthorizeValue)
}

fun hasPreAuthorize(annotations: List<AnnotationTree>): Boolean {
    return annotations.any { controllerPreAuthorizeSimpleAnnotationName(it) == "PreAuthorize" }
}

fun hasPreAuthorizeExpression(annotations: List<AnnotationTree>, expression: String): Boolean {
    return annotations.any { annotation ->
        controllerPreAuthorizeSimpleAnnotationName(annotation) == "PreAuthorize" &&
            annotation.toString().contains(expression)
    }
}

fun collectControllerPreAuthorizeFindings(
    compilationUnit: CompilationUnitTree,
    trees: Trees,
    rootDir: File
): List<ControllerPreAuthorizeFinding> {
    val sourceFile = File(compilationUnit.sourceFile.toUri())
    val sourcePath = sourceFile.controllerPreAuthorizeRelativeUnixPath(rootDir)
    val sourceText = sourceFile.readText()
    val findings = mutableListOf<ControllerPreAuthorizeFinding>()

    object : TreePathScanner<Unit, Unit>() {
        override fun visitClass(node: ClassTree, unused: Unit?) {
            if (hasControllerAnnotation(node)) {
                val classStart = trees.sourcePositions.getStartPosition(compilationUnit, node).toInt()
                val classHeader = sourceText.substring(
                    classStart,
                    minOf(sourceText.length, classStart + 500)
                )

                val isAdminOnlyController = classHeader.contains("@PreAuthorize(\"hasRole('ADMIN')\")")

                if (!isAdminOnlyController && !classHeader.contains("@PreAuthorize(\"denyAll()\")")) {
                    findings += ControllerPreAuthorizeFinding(
                        sourcePath,
                        compilationUnit.lineMap.getLineNumber(trees.sourcePositions.getStartPosition(compilationUnit, node)),
                        "controller ${node.simpleName} must have top-level @PreAuthorize(\"denyAll()\")"
                    )
                }

                if (!isAdminOnlyController) {
                    node.members
                        .filterIsInstance<MethodTree>()
                        .filter(::hasRouteAnnotation)
                        .filter { method -> !hasPreAuthorize(method.modifiers.annotations) }
                        .forEach { method ->
                            findings += ControllerPreAuthorizeFinding(
                                sourcePath,
                                compilationUnit.lineMap.getLineNumber(trees.sourcePositions.getStartPosition(compilationUnit, method)),
                                "route method ${node.simpleName}.${method.name} must have method-level @PreAuthorize"
                            )
                        }
                }
            }

            super.visitClass(node, unused)
        }
    }.scan(compilationUnit, Unit)

    return findings
}

fun inspectSourceSetForControllerPreAuthorize(sourceSet: SourceSet, rootDir: File): List<ControllerPreAuthorizeFinding> {
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
            controllerPreAuthorizeCompilerOptionsFor(sourceSet),
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

            throw GradleException("Failed to analyze Java source files before checking controller @PreAuthorize policy:\n$message")
        }

        return parsedUnits.flatMap { compilationUnit ->
            collectControllerPreAuthorizeFindings(compilationUnit, trees, rootDir)
        }
    }
}

fun controllerPreAuthorizeFailureGuidance(): String {
    return """

CONTROLLER PREAUTHORIZE POLICY FAILURE

Put @PreAuthorize("denyAll()") on every non-admin @Controller or @RestController.
Then put a method-level @PreAuthorize expression on each route method.

The only controller-wide exception is @PreAuthorize("hasRole('ADMIN')"), which marks an
entire controller as admin-only.
""".trimIndent()
}

val requireControllerPreAuthorize by tasks.registering {
    group = "verification"
    description = "Fails the build when controllers lack class and route-level @PreAuthorize annotations."

    val javaExtension = project.extensions.getByType<JavaPluginExtension>()
    val sourceSets = javaExtension.sourceSets

    sourceSets.configureEach {
        inputs.files(allJava)
        inputs.files(compileClasspath)
    }

    doLast {
        val findings = sourceSets.flatMap { sourceSet ->
            inspectSourceSetForControllerPreAuthorize(sourceSet, rootProject.projectDir)
        }

        if (findings.isNotEmpty()) {
            throw GradleException(
                "Controller @PreAuthorize policy violations found:\n" +
                    findings.sortedWith(compareBy({ it.sourcePath }, { it.lineNumber }, { it.message }))
                        .joinToString("\n") { " - ${it.sourcePath}:${it.lineNumber} ${it.message}." } +
                    "\n\n" +
                    controllerPreAuthorizeFailureGuidance()
            )
        }
    }
}

tasks.matching { it.name == "check" }.configureEach {
    dependsOn(requireControllerPreAuthorize)
}
