/*
 * DESIGN BUILD GATE: NAMESPACE CLASS ENFORCEMENT
 *
 * Java packages and folders are the project namespace mechanism. A class whose public API is
 * only a bundle of public static nested classes is not a real domain type; it is a namespace
 * disguised as a class. Put those grouped classes in a unique sub-package instead, with each
 * public class in its own source file.
 *
 * This gate intentionally allows the "friend access" pattern where an outer class exposes
 * public static factory methods for nested public static classes that have private constructors.
 * In that shape, the nesting carries behavior: the outer class can create values that callers
 * cannot construct directly. The bad pattern is independently constructible public static nested
 * classes grouped under an outer class only to make names shorter or organized.
 */

import com.sun.source.tree.ClassTree
import com.sun.source.tree.CompilationUnitTree
import com.sun.source.tree.MethodTree
import com.sun.source.tree.Tree
import com.sun.source.tree.VariableTree
import com.sun.source.util.JavacTask
import com.sun.source.util.TreePathScanner
import com.sun.source.util.Trees
import org.gradle.api.GradleException
import org.gradle.api.plugins.JavaPluginExtension
import org.gradle.api.tasks.SourceSet
import java.io.File
import java.io.StringWriter
import java.util.Locale
import javax.lang.model.element.Modifier
import javax.tools.Diagnostic
import javax.tools.DiagnosticCollector
import javax.tools.JavaFileObject
import javax.tools.ToolProvider

data class NamespaceClassFinding(
    val lineNumber: Long,
    val className: String,
    val nestedClassNames: List<String>
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

fun ClassTree.hasModifier(modifier: Modifier): Boolean {
    return modifier in modifiers.flags
}

fun MethodTree.isConstructor(): Boolean {
    return name.contentEquals("<init>")
}

fun ClassTree.constructors(): List<MethodTree> {
    return members
        .filterIsInstance<MethodTree>()
        .filter { it.isConstructor() }
}

fun ClassTree.hasOnlyPublicConstructors(): Boolean {
    val constructors = constructors()

    return constructors.isEmpty() || constructors.all { Modifier.PUBLIC in it.modifiers.flags }
}

fun ClassTree.hasNonPrivateConstructor(): Boolean {
    val constructors = constructors()

    return constructors.isEmpty() || constructors.any { Modifier.PRIVATE !in it.modifiers.flags }
}

fun ClassTree.publicNestedClasses(): List<ClassTree> {
    return members
        .filterIsInstance<ClassTree>()
        .filter { it.hasModifier(Modifier.PUBLIC) }
}

fun ClassTree.publicStaticNestedClasses(): List<ClassTree> {
    return publicNestedClasses()
        .filter { it.kind == Tree.Kind.CLASS && it.hasModifier(Modifier.STATIC) }
}

fun ClassTree.hasInstanceMemberStateOrBehavior(): Boolean {
    return members.any { member ->
        when (member) {
            is VariableTree ->
                Modifier.STATIC !in member.modifiers.flags
            is MethodTree ->
                !member.isConstructor() && Modifier.STATIC !in member.modifiers.flags
            else ->
                false
        }
    }
}

fun ClassTree.hasOnlyStaticPublicSurface(): Boolean {
    val publicMembers = members.filter { member ->
        when (member) {
            is ClassTree -> member.hasModifier(Modifier.PUBLIC)
            is MethodTree -> Modifier.PUBLIC in member.modifiers.flags
            is VariableTree -> Modifier.PUBLIC in member.modifiers.flags
            else -> false
        }
    }

    return publicMembers.all { member ->
        when (member) {
            is MethodTree ->
                !member.isConstructor() && Modifier.STATIC in member.modifiers.flags
            is VariableTree ->
                Modifier.STATIC in member.modifiers.flags
            is ClassTree ->
                member.kind == Tree.Kind.CLASS && member.hasModifier(Modifier.STATIC)
            else ->
                false
        }
    }
}

fun isNamespaceClass(classTree: ClassTree): Boolean {
    if (classTree.kind != Tree.Kind.CLASS || !classTree.hasModifier(Modifier.PUBLIC)) {
        return false
    }

    if (classTree.extendsClause != null) {
        return false
    }

    if (classTree.hasNonPrivateConstructor() || classTree.hasInstanceMemberStateOrBehavior()) {
        return false
    }

    if (!classTree.hasOnlyStaticPublicSurface()) {
        return false
    }

    val publicNestedClasses = classTree.publicNestedClasses()
    val publicStaticNestedClasses = classTree.publicStaticNestedClasses()

    return publicStaticNestedClasses.isNotEmpty() &&
        publicNestedClasses.size == publicStaticNestedClasses.size &&
        publicStaticNestedClasses.all { it.hasOnlyPublicConstructors() }
}

fun qualifiedClassName(packageName: String, classStack: List<String>, currentName: String): String {
    val nestedName = (classStack + currentName).joinToString(".")

    return if (packageName.isBlank()) {
        nestedName
    } else {
        "$packageName.$nestedName"
    }
}

fun collectNamespaceClassFindings(
    compilationUnit: CompilationUnitTree,
    trees: Trees
): List<NamespaceClassFinding> {
    val findings = mutableListOf<NamespaceClassFinding>()
    val packageName = compilationUnit.packageName?.toString().orEmpty()
    val classStack = mutableListOf<String>()

    object : TreePathScanner<Unit, Unit>() {
        override fun visitClass(node: ClassTree, unused: Unit?) {
            val className = node.simpleName.toString()

            if (isNamespaceClass(node)) {
                val nestedClassNames = node.publicStaticNestedClasses()
                    .map { it.simpleName.toString() }
                    .sorted()

                findings += NamespaceClassFinding(
                    lineNumber = sourceLine(compilationUnit, node, trees),
                    className = qualifiedClassName(packageName, classStack, className),
                    nestedClassNames = nestedClassNames
                )
            }

            classStack += className
            super.visitClass(node, unused)
            classStack.removeLast()
        }
    }.scan(compilationUnit, Unit)

    return findings
}

fun inspectSourceSetForNamespaceClasses(sourceSet: SourceSet, rootDir: File): List<String> {
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

            throw GradleException("Failed to analyze Java source files before checking namespace classes:\n$message")
        }

        return parsedUnits.flatMap { compilationUnit ->
            val sourceFile = File(compilationUnit.sourceFile.toUri())
            val sourcePath = sourceFile.relativeUnixPath(rootDir)

            collectNamespaceClassFindings(compilationUnit, trees).map { finding ->
                "$sourcePath:${finding.lineNumber} ${finding.className} groups independently constructible public static nested classes (${finding.nestedClassNames.joinToString(", ")})."
            }
        }
    }
}

fun namespaceClassFailureGuidance(): String {
    return """

NAMESPACE CLASS POLICY FAILURE

Goal:
Use Java packages and folders to group related types. Do not create a class whose job is only
to act as a namespace for other public classes. Each public class should live in its own .java
file, under a package name that communicates the grouping.

Bad pattern:
- public final class RouteValues { private RouteValues() {} public static final class TaskId { public TaskId(...) {...} } }
- Callers refer to RouteValues.TaskId only because RouteValues is being used like a folder.
- The nested public static classes have public constructors, so the outer class is not providing
  controlled construction or meaningful encapsulation.

Good pattern:
- Put TaskId, CommentId, and related values in a routevalues/ folder with package
  com.example...routevalues.
- Keep each public value type in its own file, such as routevalues/TaskId.java.
- Use nesting only when the outer class has real behavior or when public static factory methods
  create nested values through private constructors to intentionally gain friend-like access.

Important instruction for AI/code-generation tools:
Do not fix this by adding an allow comment or making the outer namespace less visible. Move the
nested public classes into a specific sub-package and update callers to import those types directly.
""".trimIndent()
}

val forbidNamespaceClasses by tasks.registering {
    group = "verification"
    description = "Fails the build when a public class is used as a namespace for public static nested classes."

    val javaExtension = project.extensions.getByType<JavaPluginExtension>()
    val sourceSets = javaExtension.sourceSets

    sourceSets.configureEach {
        inputs.files(allJava)
        inputs.files(compileClasspath)
    }

    doLast {
        val violations = sourceSets.flatMap { sourceSet ->
            inspectSourceSetForNamespaceClasses(sourceSet, rootProject.projectDir)
        }

        if (violations.isNotEmpty()) {
            throw GradleException(
                "Namespace classes found:\n" +
                    violations.joinToString("\n") { " - $it" } +
                    "\n\n" +
                    namespaceClassFailureGuidance()
            )
        }
    }
}

tasks.matching { it.name == "check" }.configureEach {
    dependsOn(forbidNamespaceClasses)
}
