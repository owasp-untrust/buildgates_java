/*
 * SECURITY BUILD GATE: STRING CONCATENATION ENFORCEMENT
 *
 * This Gradle script fails the build when Java source files use string concatenation with '+'
 * outside a narrowly documented safe scope.
 *
 * A safe scope must be opened with a comment containing:
 *
 *     STRING CONCAT IS SAFE HERE: <reason>
 *
 * and closed with a later comment containing:
 *
 *     END STRING CONCAT
 *
 * Line comments and block comments are both accepted. The opening and closing comments must be
 * inside the same method, constructor, initializer block, or lambda body. The reason length is
 * configured in string_concat_guardrail.json and defaults to 200 characters when omitted.
 */

import com.sun.source.tree.BinaryTree
import com.sun.source.tree.BlockTree
import com.sun.source.tree.ClassTree
import com.sun.source.tree.CompilationUnitTree
import com.sun.source.tree.LambdaExpressionTree
import com.sun.source.tree.LiteralTree
import com.sun.source.tree.MemberSelectTree
import com.sun.source.tree.MethodInvocationTree
import com.sun.source.tree.MethodTree
import com.sun.source.tree.NewClassTree
import com.sun.source.tree.ParenthesizedTree
import com.sun.source.tree.Tree
import com.sun.source.tree.VariableTree
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
import javax.lang.model.type.DeclaredType
import javax.lang.model.type.TypeKind
import javax.tools.Diagnostic
import javax.tools.DiagnosticCollector
import javax.tools.JavaFileObject
import javax.tools.ToolProvider

val DEFAULT_MINIMUM_REASON_CHARACTERS = 200
val OPEN_MARKER = "STRING CONCAT IS SAFE HERE:"
val CLOSE_MARKER = "END STRING CONCAT"
val STRING_CONCATENATION_SAFE_ANNOTATION_NAME = "org.owasp.untrust.buildmetadata.StringConcatenationSafe"
@Suppress("UNCHECKED_CAST")
val readJsonConfigObject = rootProject.extensions.extraProperties["readJsonConfigObject"] as (File) -> Map<String, Any?>
val RAW_STRING_ASSEMBLY_TYPES = mapOf(
    "java.lang.StringBuilder" to "StringBuilder",
    "java.lang.StringBuffer" to "StringBuffer",
    "java.io.StringWriter" to "StringWriter",
    "java.io.CharArrayWriter" to "CharArrayWriter",
    "java.io.PrintWriter" to "PrintWriter",
    "com.google.common.base.Joiner" to "Guava Joiner"
)

data class StringConcatGuardConfig(
    val minimumReasonCharacters: Int
)

data class SourceLineComment(
    val lineNumber: Long,
    val text: String
)

data class StringConcatScope(
    val startLine: Long,
    val endLine: Long,
    val description: String
)

data class StringConcatSafeRegion(
    val openLine: Long,
    val closeLine: Long,
    val reason: String,
    val scope: StringConcatScope
)

data class PendingStringConcatRegion(
    val openLine: Long,
    val reason: String,
    val scope: StringConcatScope
)

data class StringConcatFinding(
    val lineNumber: Long,
    val kind: String,
    val expression: String
)

fun File.relativeUnixPath(rootDir: File): String {
    return rootDir.toPath()
        .relativize(toPath())
        .toString()
        .replace(File.separatorChar, '/')
}

fun readStringConcatGuardConfig(file: File): StringConcatGuardConfig {
    if (!file.exists()) {
        return StringConcatGuardConfig(DEFAULT_MINIMUM_REASON_CHARACTERS)
    }

    val parsed = readJsonConfigObject(file)

    val rawMinimum = parsed["minimumReasonCharacters"]
        ?: return StringConcatGuardConfig(DEFAULT_MINIMUM_REASON_CHARACTERS)

    val minimum = when (rawMinimum) {
        is Number -> rawMinimum.toInt()
        is String -> rawMinimum.toIntOrNull()
        else -> null
    } ?: throw GradleException("string_concat_guardrail.json field 'minimumReasonCharacters' must be an integer.")

    if (minimum < 1) {
        throw GradleException("string_concat_guardrail.json field 'minimumReasonCharacters' must be at least 1.")
    }

    return StringConcatGuardConfig(minimum)
}

fun normalizeCommentLine(text: String): String {
    return text
        .trim()
        .removePrefix("//")
        .removePrefix("/*")
        .removePrefix("*")
        .removeSuffix("*/")
        .trim()
}

fun extractComments(sourceFile: File): List<SourceLineComment> {
    val comments = mutableListOf<SourceLineComment>()
    var inBlockComment = false
    var blockCommentText = StringBuilder()
    var blockCommentStartLine = -1L

    sourceFile.readLines().forEachIndexed { index, rawLine ->
        var remaining = rawLine
        val lineNumber = index + 1L

        while (remaining.isNotEmpty()) {
            if (inBlockComment) {
                val closeIndex = remaining.indexOf("*/")

                if (closeIndex >= 0) {
                    blockCommentText.append(' ')
                    blockCommentText.append(remaining.substring(0, closeIndex))
                    comments += SourceLineComment(
                        lineNumber = blockCommentStartLine,
                        text = normalizeCommentLine(blockCommentText.toString())
                    )
                    blockCommentText = StringBuilder()
                    blockCommentStartLine = -1L
                    inBlockComment = false
                    remaining = remaining.substring(closeIndex + 2)
                } else {
                    blockCommentText.append(' ')
                    blockCommentText.append(remaining)
                    remaining = ""
                }
            } else {
                val lineCommentIndex = remaining.indexOf("//")
                val blockCommentIndex = remaining.indexOf("/*")

                when {
                    lineCommentIndex < 0 && blockCommentIndex < 0 -> remaining = ""
                    lineCommentIndex >= 0 && (blockCommentIndex < 0 || lineCommentIndex < blockCommentIndex) -> {
                        comments += SourceLineComment(
                            lineNumber = lineNumber,
                            text = normalizeCommentLine(remaining.substring(lineCommentIndex))
                        )
                        remaining = ""
                    }
                    else -> {
                        val afterOpen = remaining.substring(blockCommentIndex + 2)
                        val closeIndex = afterOpen.indexOf("*/")

                        if (closeIndex >= 0) {
                            comments += SourceLineComment(
                                lineNumber = lineNumber,
                                text = normalizeCommentLine(afterOpen.substring(0, closeIndex))
                            )
                            remaining = afterOpen.substring(closeIndex + 2)
                        } else {
                            inBlockComment = true
                            blockCommentStartLine = lineNumber
                            blockCommentText.append(afterOpen)
                            remaining = ""
                        }
                    }
                }
            }
        }
    }

    if (inBlockComment) {
        comments += SourceLineComment(
            lineNumber = blockCommentStartLine,
            text = normalizeCommentLine(blockCommentText.toString())
        )
    }

    return comments
}

fun StringConcatScope.contains(lineNumber: Long): Boolean {
    return lineNumber in startLine..endLine
}

fun smallestScopeForLine(scopes: List<StringConcatScope>, lineNumber: Long): StringConcatScope? {
    return scopes
        .filter { it.contains(lineNumber) }
        .minByOrNull { it.endLine - it.startLine }
}

fun sourceLine(compilationUnit: CompilationUnitTree, tree: Tree, trees: Trees): Long {
    val startPosition = trees.sourcePositions.getStartPosition(compilationUnit, tree)

    return if (startPosition >= 0) {
        compilationUnit.lineMap.getLineNumber(startPosition)
    } else {
        -1L
    }
}

fun sourceEndLine(compilationUnit: CompilationUnitTree, tree: Tree, trees: Trees): Long {
    val endPosition = trees.sourcePositions.getEndPosition(compilationUnit, tree)

    return if (endPosition >= 0) {
        compilationUnit.lineMap.getLineNumber(endPosition)
    } else {
        sourceLine(compilationUnit, tree, trees)
    }
}

fun executableScopes(compilationUnit: CompilationUnitTree, trees: Trees): List<StringConcatScope> {
    val scopes = mutableListOf<StringConcatScope>()

    object : TreePathScanner<Unit, Unit>() {
        override fun visitMethod(node: MethodTree, unused: Unit?) {
            val body = node.body

            if (body != null) {
                val name = if (node.name.contentEquals("<init>")) {
                    "constructor"
                } else {
                    "method ${node.name}"
                }

                scopes += StringConcatScope(
                    startLine = sourceLine(compilationUnit, body, trees),
                    endLine = sourceEndLine(compilationUnit, body, trees),
                    description = name
                )
            }

            super.visitMethod(node, unused)
        }

        override fun visitLambdaExpression(node: LambdaExpressionTree, unused: Unit?) {
            scopes += StringConcatScope(
                startLine = sourceLine(compilationUnit, node.body, trees),
                endLine = sourceEndLine(compilationUnit, node.body, trees),
                description = "lambda"
            )

            super.visitLambdaExpression(node, unused)
        }

        override fun visitClass(node: ClassTree, unused: Unit?) {
            node.members
                .filterIsInstance<BlockTree>()
                .forEach { block ->
                    val description = if (block.isStatic) {
                        "static initializer"
                    } else {
                        "initializer"
                    }

                    scopes += StringConcatScope(
                        startLine = sourceLine(compilationUnit, block, trees),
                        endLine = sourceEndLine(compilationUnit, block, trees),
                        description = description
                    )
                }

            super.visitClass(node, unused)
        }
    }.scan(compilationUnit, Unit)

    return scopes
}

fun validateSafeRegions(
    comments: List<SourceLineComment>,
    scopes: List<StringConcatScope>,
    minimumReasonCharacters: Int,
    sourcePath: String
): Pair<List<StringConcatSafeRegion>, List<String>> {
    val safeRegions = mutableListOf<StringConcatSafeRegion>()
    val violations = mutableListOf<String>()
    val openRegionsByScope = mutableMapOf<StringConcatScope, PendingStringConcatRegion>()

    for (comment in comments.sortedBy { it.lineNumber }) {
        val hasOpenMarker = comment.text.contains(OPEN_MARKER)
        val hasCloseMarker = comment.text.contains(CLOSE_MARKER)

        if (hasOpenMarker) {
            val scope = smallestScopeForLine(scopes, comment.lineNumber)

            if (scope == null) {
                violations += "$sourcePath:${comment.lineNumber} opens a string concatenation safe region outside an executable scope."
                continue
            }

            if (openRegionsByScope.containsKey(scope)) {
                violations += "$sourcePath:${comment.lineNumber} opens a nested string concatenation safe region inside ${scope.description}; close the previous region first."
                continue
            }

            val reason = comment.text.substringAfter(OPEN_MARKER).trim()

            if (reason.length < minimumReasonCharacters) {
                violations += "$sourcePath:${comment.lineNumber} string concatenation safe reason is ${reason.length} characters; minimum is $minimumReasonCharacters."
            }

            openRegionsByScope[scope] = PendingStringConcatRegion(
                openLine = comment.lineNumber,
                reason = reason,
                scope = scope
            )
        }

        if (hasCloseMarker) {
            val scope = smallestScopeForLine(scopes, comment.lineNumber)

            if (scope == null) {
                violations += "$sourcePath:${comment.lineNumber} closes a string concatenation safe region outside an executable scope."
                continue
            }

            val pending = openRegionsByScope.remove(scope)

            if (pending == null) {
                violations += "$sourcePath:${comment.lineNumber} closes a string concatenation safe region in ${scope.description} without a matching opening comment."
                continue
            }

            safeRegions += StringConcatSafeRegion(
                openLine = pending.openLine,
                closeLine = comment.lineNumber,
                reason = pending.reason,
                scope = scope
            )
        }
    }

    openRegionsByScope.values.forEach { pending ->
        violations += "$sourcePath:${pending.openLine} opens a string concatenation safe region in ${pending.scope.description} without a matching closing comment."
    }

    return safeRegions to violations
}

fun isStringConcat(binaryTree: BinaryTree, scanner: TreePathScanner<*, *>, trees: Trees): Boolean {
    if (binaryTree.kind != Tree.Kind.PLUS) {
        return false
    }

    val typeMirror = trees.getTypeMirror(scanner.currentPath)

    return typeMirror != null &&
        typeMirror.kind != TypeKind.ERROR &&
        typeMirror.toString() == "java.lang.String"
}

fun isStringLiteral(tree: Tree): Boolean {
    return tree is LiteralTree && tree.value is String
}

fun isStringConcatenationSafeExpression(treePath: TreePath, trees: Trees): Boolean {
    val typeMirror = trees.getTypeMirror(treePath)

    return typeMirror != null &&
        typeMirror.kind != TypeKind.ERROR &&
        typeMirror is DeclaredType &&
        typeMirror.asElement().annotationMirrors.any { annotationMirror ->
            annotationMirror.annotationType.toString() == STRING_CONCATENATION_SAFE_ANNOTATION_NAME
        }
}

fun isAllowedStringConcatOperand(treePath: TreePath, trees: Trees): Boolean {
    val leaf = treePath.leaf

    return when {
        leaf is ParenthesizedTree -> isAllowedStringConcatOperand(TreePath(treePath, leaf.expression), trees)
        leaf is BinaryTree && leaf.kind == Tree.Kind.PLUS -> isAllowedSafeStringConcat(treePath, leaf, trees)
        isStringLiteral(leaf) -> true
        else -> isStringConcatenationSafeExpression(treePath, trees)
    }
}

fun isAllowedSafeStringConcat(treePath: TreePath, binaryTree: BinaryTree, trees: Trees): Boolean {
    return isAllowedStringConcatOperand(TreePath(treePath, binaryTree.leftOperand), trees) &&
        isAllowedStringConcatOperand(TreePath(treePath, binaryTree.rightOperand), trees)
}

fun treeTypeName(treePath: TreePath, trees: Trees): String? {
    val typeMirror = trees.getTypeMirror(treePath) ?: return null

    return if (typeMirror.kind == TypeKind.ERROR) {
        null
    } else {
        typeMirror.toString()
    }
}

fun selectedMethodOwner(methodInvocationTree: MethodInvocationTree, scanner: TreePathScanner<*, *>, trees: Trees): String? {
    val element = trees.getElement(TreePath(scanner.currentPath, methodInvocationTree.methodSelect))
        ?: return null

    return element.enclosingElement?.toString()
}

fun stringConcatFailureGuidance(minimumReasonCharacters: Int): String {
    return """

STRING CONCATENATION POLICY FAILURE

This failure is not asking you to find a different raw string-building API.

Do not replace the violating code with another non-structure-aware string assembly mechanism such as:
- StringBuilder
- StringBuffer
- StringWriter
- CharArrayWriter
- PrintWriter used as a string accumulator
- Collectors.joining
- String.join
- String.format
- MessageFormat.format
- String.concat
- String.formatted
- manual loops that append or print values into an unstructured string

That kind of rewrite may make one detector pass, but it violates the purpose of this build gate.

Required reasoning path:

1. First ask whether this string-producing code should exist at all.
   If the violating method or helper is only a generic raw concatenation utility, such as TextOutput.parts(...),
   it should usually be removed instead of reimplemented with a different low-level API.

2. Identify the semantic context of the output being built.
   Examples:
   - SQL should be built with a SQL DSL or parameterized query API.
   - HTML/XML should be built with a template engine, DOM builder, or escaping-aware renderer.
   - JSON should be built with a JSON serializer.
   - URLs should be built with a URI/URL builder.
   - filesystem paths should be built with path APIs.
   - log messages should use the logging framework's structured/template API.
   - user-facing validation errors should use a structured error object, message code, or framework-supported message source when available.

3. Search the existing project first for an approved structured, context-aware builder or renderer.
   If none exists, consider whether adding a focused dependency or small domain-specific abstraction is the right fix.
   The goal is not "a string without using +"; the goal is "a safe representation for this specific context."

4. Only if raw concatenation is genuinely unavoidable, keep it local and explicitly justified.
   Do not hide it inside a generic helper whose purpose is to bypass this guardrail.
   Surround only the minimum necessary code with the approved comments.

Allowed exception format:

   /* STRING CONCAT IS SAFE HERE: 
    * <specific justification of at least $minimumReasonCharacters characters explaining:
    * - why no structured/context-aware builder fits this case
    * - why raw concatenation is necessary here
    * - what data can flow into the concatenation
    * - how malicious or user-controlled input is made safe
    * - why the exception scope is intentionally narrow>
    */
   String s = somePart + someOtherPart;
   ... more directly related concatenation code here ...
   /* END STRING CONCAT */

Line comments are also accepted:

   // STRING CONCAT IS SAFE HERE: 
   // <specific justification of at least $minimumReasonCharacters characters explaining why no structured/context-aware builder fits,
   // why raw concatenation is necessary, what data can flow in, and how user-controlled input is made safe>
   String s = somePart + someOtherPart;
   // END STRING CONCAT

The opening and closing comments must be in the same method, constructor, initializer block, or lambda body.

Important instruction for AI/code-generation tools:
If you are an AI assistant or automated code generator, do not respond to this failure by inventing another raw string-concatenation helper.
Either replace the code with a structured, context-aware API appropriate to the output domain, remove the unnecessary generic helper, or ask the human for approval to add a narrow documented exception.
""".trimIndent()
}

fun forbiddenStringAssemblyMethod(
    methodInvocationTree: MethodInvocationTree,
    scanner: TreePathScanner<*, *>,
    trees: Trees
): String? {
    val methodSelect = methodInvocationTree.methodSelect

    if (methodSelect is MemberSelectTree) {
        val methodName = methodSelect.identifier.toString()
        val owner = selectedMethodOwner(methodInvocationTree, scanner, trees)

        if (
            methodName in setOf("concat", "formatted") &&
            treeTypeName(TreePath(scanner.currentPath, methodSelect.expression), trees) == "java.lang.String"
        ) {
            return "String.$methodName"
        }

        if (methodName == "join" && owner == "java.lang.String") {
            return "String.join"
        }

        if (methodName == "format" && owner == "java.lang.String") {
            return "String.format"
        }

        if (methodName == "joining" && owner == "java.util.stream.Collectors") {
            return "Collectors.joining"
        }

        if (
            methodName == "format" &&
            (owner == "java.text.MessageFormat" || methodSelect.expression.toString() in setOf("Message", "java.text.MessageFormat", "MessageFormat"))
        ) {
            return "$owner.format"
        }
    } else if (methodSelect.toString() == "join" && selectedMethodOwner(methodInvocationTree, scanner, trees) == "java.lang.String") {
        return "String.join"
    } else if (methodSelect.toString() == "joining" && selectedMethodOwner(methodInvocationTree, scanner, trees) == "java.util.stream.Collectors") {
        return "Collectors.joining"
    } else if (methodSelect.toString() == "format") {
        val owner = selectedMethodOwner(methodInvocationTree, scanner, trees)

        if (owner == "java.lang.String") {
            return "String.format"
        }

        if (owner in setOf("java.text.MessageFormat", "Message")) {
            return "$owner.format"
        }
    }

    return null
}

fun findStringConcats(compilationUnit: CompilationUnitTree, trees: Trees): List<StringConcatFinding> {
    val findings = linkedMapOf<Long, StringConcatFinding>()

    fun forbiddenRawStringAssemblyKind(treePath: TreePath): String? {
        return RAW_STRING_ASSEMBLY_TYPES[treeTypeName(treePath, trees)]
    }

    object : TreePathScanner<Unit, Unit>() {
        override fun visitBinary(node: BinaryTree, unused: Unit?) {
            if (isStringConcat(node, this, trees) && !isAllowedSafeStringConcat(currentPath, node, trees)) {
                val lineNumber = sourceLine(compilationUnit, node, trees)

                if (lineNumber > 0 && !findings.containsKey(lineNumber)) {
                    findings[lineNumber] = StringConcatFinding(
                        lineNumber = lineNumber,
                        kind = "string concatenation",
                        expression = node.toString()
                    )
                }
            }

            super.visitBinary(node, unused)
        }

        override fun visitMethodInvocation(node: MethodInvocationTree, unused: Unit?) {
            val forbiddenMethod = forbiddenStringAssemblyMethod(node, this, trees)

            if (forbiddenMethod != null) {
                val lineNumber = sourceLine(compilationUnit, node, trees)

                if (lineNumber > 0 && !findings.containsKey(lineNumber)) {
                    findings[lineNumber] = StringConcatFinding(
                        lineNumber = lineNumber,
                        kind = forbiddenMethod,
                        expression = node.toString()
                    )
                }
            }

            super.visitMethodInvocation(node, unused)
        }

        override fun visitNewClass(node: NewClassTree, unused: Unit?) {
            val forbiddenType = forbiddenRawStringAssemblyKind(currentPath)

            if (forbiddenType != null) {
                val lineNumber = sourceLine(compilationUnit, node, trees)

                if (lineNumber > 0 && !findings.containsKey(lineNumber)) {
                    findings[lineNumber] = StringConcatFinding(
                        lineNumber = lineNumber,
                        kind = forbiddenType,
                        expression = node.toString()
                    )
                }
            }

            super.visitNewClass(node, unused)
        }

        override fun visitVariable(node: VariableTree, unused: Unit?) {
            val typeTree = node.type
            val forbiddenType = if (typeTree == null) {
                null
            } else {
                forbiddenRawStringAssemblyKind(TreePath(currentPath, typeTree))
            }

            if (forbiddenType != null) {
                val lineNumber = sourceLine(compilationUnit, node, trees)

                if (lineNumber > 0 && !findings.containsKey(lineNumber)) {
                    findings[lineNumber] = StringConcatFinding(
                        lineNumber = lineNumber,
                        kind = forbiddenType,
                        expression = node.toString()
                    )
                }
            }

            super.visitVariable(node, unused)
        }
    }.scan(compilationUnit, Unit)

    return findings.values.toList()
}

fun stringConcatAllowed(
    finding: StringConcatFinding,
    safeRegions: List<StringConcatSafeRegion>
): Boolean {
    return safeRegions.any { region ->
        finding.lineNumber in region.openLine..region.closeLine &&
            region.scope.contains(finding.lineNumber)
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

fun inspectSourceSetForStringConcat(
    sourceSet: SourceSet,
    rootDir: File,
    config: StringConcatGuardConfig
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
        task.analyze()

        val errors = diagnostics.diagnostics
            .filter { it.kind == Diagnostic.Kind.ERROR }

        if (errors.isNotEmpty()) {
            val message = errors.joinToString("\n") { diagnostic ->
                val sourceName = diagnostic.source?.name ?: "<unknown source>"
                " - $sourceName:${diagnostic.lineNumber}: ${diagnostic.getMessage(Locale.ROOT)}"
            }

            throw GradleException("Failed to analyze Java source files before checking string concatenation:\n$message")
        }

        return parsedUnits.flatMap { compilationUnit ->
            val sourceFile = File(compilationUnit.sourceFile.toUri())
            val sourcePath = sourceFile.relativeUnixPath(rootDir)
            val scopes = executableScopes(compilationUnit, trees)
            val (safeRegions, regionViolations) = validateSafeRegions(
                comments = extractComments(sourceFile),
                scopes = scopes,
                minimumReasonCharacters = config.minimumReasonCharacters,
                sourcePath = sourcePath
            )

            val concatViolations = findStringConcats(compilationUnit, trees)
                .filterNot { stringConcatAllowed(it, safeRegions) }
                .map { finding ->
                    "$sourcePath:${finding.lineNumber} uses forbidden ${finding.kind} outside a STRING CONCAT IS SAFE HERE / END STRING CONCAT scope: ${finding.expression}"
                }

            regionViolations + concatViolations
        }
    }
}

val forbidStringConcat by tasks.registering {
    group = "verification"
    description = "Fails the build when Java string concatenation is used outside documented safe scopes."

    val configFile = (rootProject.extensions.extraProperties["rootJsonConfigFile"] as (String) -> File)("string_concat_guardrail.json")
    val javaExtension = project.extensions.getByType<JavaPluginExtension>()
    val sourceSets = javaExtension.sourceSets

    inputs.file(configFile).optional()
    sourceSets.configureEach {
        inputs.files(allJava)
        inputs.files(compileClasspath)
    }

    doLast {
        val config = readStringConcatGuardConfig(configFile)
        val violations = sourceSets.flatMap { sourceSet ->
            inspectSourceSetForStringConcat(sourceSet, rootProject.projectDir, config)
        }

        if (violations.isNotEmpty()) {
            throw GradleException(
                "Forbidden string concatenation found:\n" +
                    violations.joinToString("\n") { " - $it" } +
                    "\n\n" +
                    stringConcatFailureGuidance(config.minimumReasonCharacters)
            )
        }
    }
}

tasks.matching { it.name == "check" }.configureEach {
    dependsOn(forbidStringConcat)
}
