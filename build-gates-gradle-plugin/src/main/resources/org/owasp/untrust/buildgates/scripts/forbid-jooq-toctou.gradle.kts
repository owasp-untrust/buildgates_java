/*
 * SECURITY BUILD GATE: JOOQ TOCTOU ENFORCEMENT
 *
 * This Gradle script fails the build when Java methods do a jOOQ read and then later execute
 * a jOOQ UPDATE or DELETE in the same method. That "check then act" shape is a common
 * time-of-check/time-of-use race: another transaction can change the row after the read and
 * before the write.
 *
 * Prefer one atomic SQL statement and use the affected row count as the existence/result signal.
 *
 * Escape hatch:
 *
 *     // ALLOW JOOQ TOCTOU: <specific justification>
 *     dsl.update(TABLE)
 *         ...
 *         .execute();
 */

import com.sun.source.tree.BlockTree
import com.sun.source.tree.CompilationUnitTree
import com.sun.source.tree.MemberSelectTree
import com.sun.source.tree.MethodInvocationTree
import com.sun.source.tree.MethodTree
import com.sun.source.tree.Tree
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
import javax.tools.Diagnostic
import javax.tools.DiagnosticCollector
import javax.tools.JavaFileObject
import javax.tools.ToolProvider

data class JooqToctouFinding(
    val methodName: String,
    val readLineNumber: Long,
    val readExpression: String,
    val writeLineNumber: Long,
    val writeExpression: String,
    val writeType: String
)

data class JooqRead(
    val lineNumber: Long,
    val expression: String
)

data class JooqWrite(
    val lineNumber: Long,
    val expression: String,
    val type: String
)

val JOOQ_TOCTOU_ALLOW_MARKER = "ALLOW JOOQ TOCTOU:"
val MINIMUM_JOOQ_TOCTOU_ALLOW_REASON_CHARACTERS = 120
val JOOQ_READ_TERMINALS = setOf(
    "fetch",
    "fetchAny",
    "fetchCount",
    "fetchExists",
    "fetchOne",
    "fetchOptional"
)
val JOOQ_MUTATING_QUERY_PREFIXES = listOf(
    "org.jooq.Update",
    "org.jooq.Delete"
)
@Suppress("UNCHECKED_CAST")
val precedingEscapeValidationProblem = rootProject.extensions.extraProperties["precedingEscapeValidationProblem"] as (File, Long, String, Int, String, Boolean) -> String?
@Suppress("UNCHECKED_CAST")
val precedingEscapeHatchUsage = rootProject.extensions.extraProperties["precedingEscapeHatchUsage"] as (String, Int, String) -> String

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

fun methodName(methodInvocationTree: MethodInvocationTree): String? {
    val methodSelect = methodInvocationTree.methodSelect

    return when (methodSelect) {
        is MemberSelectTree -> methodSelect.identifier.toString()
        else -> null
    }
}

fun receiverType(methodInvocationTree: MethodInvocationTree, currentPath: TreePath, trees: Trees): TypeMirror? {
    val methodSelect = methodInvocationTree.methodSelect

    return when (methodSelect) {
        is MemberSelectTree -> trees.getTypeMirror(TreePath(currentPath, methodSelect.expression))
        else -> null
    }
}

fun isConcreteType(typeMirror: TypeMirror?): Boolean {
    return typeMirror != null &&
        typeMirror.kind != TypeKind.ERROR &&
        typeMirror.kind != TypeKind.NULL &&
        typeMirror.kind != TypeKind.NONE &&
        typeMirror.kind != TypeKind.VOID
}

fun isJooqReadTerminal(methodInvocationTree: MethodInvocationTree, currentPath: TreePath, trees: Trees): Boolean {
    val name = methodName(methodInvocationTree)

    if (name !in JOOQ_READ_TERMINALS) {
        return false
    }

    val typeName = receiverType(methodInvocationTree, currentPath, trees)?.toString().orEmpty()

    return typeName.startsWith("org.jooq.Select") ||
        typeName.startsWith("org.jooq.ResultQuery") ||
        typeName.startsWith("org.jooq.Cursor")
}

fun isJooqUpdateOrDeleteExecute(methodInvocationTree: MethodInvocationTree, currentPath: TreePath, trees: Trees): String? {
    if (methodName(methodInvocationTree) != "execute") {
        return null
    }

    val typeMirror = receiverType(methodInvocationTree, currentPath, trees)

    if (!isConcreteType(typeMirror)) {
        return null
    }

    val typeName = typeMirror.toString()

    return JOOQ_MUTATING_QUERY_PREFIXES.firstOrNull { typeName.startsWith(it) }?.let { typeName }
}

fun collectJooqToctouFindings(
    compilationUnit: CompilationUnitTree,
    trees: Trees
): List<JooqToctouFinding> {
    val findings = mutableListOf<JooqToctouFinding>()

    object : TreePathScanner<Unit, Unit>() {
        override fun visitMethod(node: MethodTree, unused: Unit?) {
            val body = node.body

            if (body != null) {
                collectMethodFindings(node.name.toString(), body)
            }
        }

        private fun collectMethodFindings(methodName: String, body: BlockTree) {
            val reads = mutableListOf<JooqRead>()
            val writes = mutableListOf<JooqWrite>()

            object : TreePathScanner<Unit, Unit>() {
                override fun visitMethodInvocation(node: MethodInvocationTree, unused: Unit?) {
                    if (isJooqReadTerminal(node, currentPath, trees)) {
                        reads += JooqRead(
                            lineNumber = sourceLine(compilationUnit, node, trees),
                            expression = node.toString()
                        )
                    }

                    val writeType = isJooqUpdateOrDeleteExecute(node, currentPath, trees)
                    if (writeType != null) {
                        writes += JooqWrite(
                            lineNumber = sourceLine(compilationUnit, node, trees),
                            expression = node.toString(),
                            type = writeType
                        )
                    }

                    super.visitMethodInvocation(node, unused)
                }
            }.scan(TreePath(currentPath, body), Unit)

            for (write in writes) {
                val priorRead = reads
                    .filter { read -> read.lineNumber in 1 until write.lineNumber }
                    .minByOrNull { read -> read.lineNumber }

                if (priorRead != null) {
                    findings += JooqToctouFinding(
                        methodName = methodName,
                        readLineNumber = priorRead.lineNumber,
                        readExpression = priorRead.expression,
                        writeLineNumber = write.lineNumber,
                        writeExpression = write.expression,
                        writeType = write.type
                    )
                }
            }
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

fun inspectSourceSetForJooqToctou(sourceSet: SourceSet, rootDir: File): List<String> {
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

            throw GradleException("Failed to analyze Java source files before checking jOOQ TOCTOU patterns:\n$message")
        }

        return parsedUnits.flatMap { compilationUnit ->
            val sourceFile = File(compilationUnit.sourceFile.toUri())
            val sourcePath = sourceFile.relativeUnixPath(rootDir)

            collectJooqToctouFindings(compilationUnit, trees).mapNotNull { finding ->
                val escapeProblem = precedingEscapeValidationProblem(
                    sourceFile,
                    finding.writeLineNumber,
                    JOOQ_TOCTOU_ALLOW_MARKER,
                    MINIMUM_JOOQ_TOCTOU_ALLOW_REASON_CHARACTERS,
                    "JOOQ TOCTOU",
                    true
                )

                if (escapeProblem == null) {
                    return@mapNotNull null
                }

                "$sourcePath:${finding.writeLineNumber} method ${finding.methodName}() executes ${finding.writeType} after a jOOQ read at line ${finding.readLineNumber}. Read: ${finding.readExpression} Write: ${finding.writeExpression} $escapeProblem"
            }
        }
    }
}

fun jooqToctouFailureGuidance(): String {
    return """

JOOQ TOCTOU POLICY FAILURE

Do not check database state with one jOOQ query and then update or delete with a later query in
the same method. Another transaction can change the row between the read and the write.

Prefer an atomic statement and use the affected row count as the result:

   int changed = dsl.update(TASKS)
       .set(DONE, true)
       .where(TASK_ID.eq(taskId))
       .execute();
   return changed > 0;

For deletes, put the authorization/existence predicate directly in the DELETE where clause and
interpret execute() the same way. If the operation truly needs a prior read, move it into a
transaction with the right locking semantics and document why that lock is required.

${precedingEscapeHatchUsage(JOOQ_TOCTOU_ALLOW_MARKER, MINIMUM_JOOQ_TOCTOU_ALLOW_REASON_CHARACTERS, "dsl.update(TABLE).set(FIELD, value).where(ID.eq(id)).execute();")}
""".trimIndent()
}

val forbidJooqToctou by tasks.registering {
    group = "verification"
    description = "Fails the build when jOOQ code uses read-then-update/delete TOCTOU-prone patterns."

    val javaExtension = project.extensions.getByType<JavaPluginExtension>()
    val sourceSets = javaExtension.sourceSets

    sourceSets.configureEach {
        inputs.files(allJava)
        inputs.files(compileClasspath)
    }

    doLast {
        val violations = sourceSets.flatMap { sourceSet ->
            inspectSourceSetForJooqToctou(sourceSet, rootProject.projectDir)
        }

        if (violations.isNotEmpty()) {
            throw GradleException(
                "jOOQ TOCTOU candidates found:\n" +
                    violations.joinToString("\n") { " - $it" } +
                    "\n\n" +
                    jooqToctouFailureGuidance()
            )
        }
    }
}

forbidJooqToctou.configure {
    mustRunAfter(tasks.matching { task -> task.name != name && task.name != "check" && task.group == "verification" })
    mustRunAfter(tasks.withType<Test>())
}

tasks.matching { it.name == "check" }.configureEach {
    dependsOn(forbidJooqToctou)
}
