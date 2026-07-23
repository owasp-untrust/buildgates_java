/*
 * SECURITY BUILD GATE: METHOD CALL ENFORCEMENT
 *
 * This Gradle script fails the build when Java source files call methods that are disallowed
 * for configured receiver types, or call methods outside a configured allow-list.
 *
 * Configuration lives in:
 *
 *     method_call_guardrail.json
 *
 * Example:
 *
 *     {
 *       "strings": {
 *         "exceptionDetails": "Avoid exposing exception details as user-viewable output"
 *       },
 *       "rules": [
 *         {
 *           "type": "java.lang.Exception",
 *           "includeSubclasses": true,
 *           "message": "$exceptionDetails",
 *           "disallowedMethods": ["getMessage", "toString"]
 *         },
 *         {
 *           "type": "com.example.SafeError",
 *           "includeSubclasses": false,
 *           "allowedMethods": ["clientMessage", "errorCode"]
 *         }
 *       ]
 *     }
 *
 * The check is type-aware. A rule for java.lang.Exception with includeSubclasses=true applies
 * to RuntimeException, IOException, and project-specific exception subclasses when the receiver
 * expression has that type.
 *
 * Escape hatch:
 *
 *     // ALLOW METHOD CALL: <specific justification>
 *     risky.methodCall()
 *
 * Multi-line // comments and block comments are accepted. The minimum justification length is
 * configured by minimumAllowReasonCharacters in method_call_guardrail.json.
 *
 * Rule message values that begin with '$' are resolved against the top-level strings map.
 */

import com.sun.source.tree.CompilationUnitTree
import com.sun.source.tree.MemberSelectTree
import com.sun.source.tree.MethodInvocationTree
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

data class MethodCallRule(
    val targetType: String,
    val includeSubclasses: Boolean,
    val message: String?,
    val allowedMethods: Set<String>,
    val disallowedMethods: Set<String>
)

data class MethodCallGuardConfig(
    val minimumAllowReasonCharacters: Int,
    val rules: List<MethodCallRule>
)

data class MethodCallFinding(
    val lineNumber: Long,
    val methodName: String,
    val receiverType: String,
    val rule: MethodCallRule,
    val reason: String
)

val DEFAULT_MINIMUM_ALLOW_REASON_CHARACTERS = 120
val ALLOW_METHOD_CALL_MARKER = "ALLOW METHOD CALL:"
@Suppress("UNCHECKED_CAST")
val readJsonConfigObject = rootProject.extensions.extraProperties["readJsonConfigObject"] as (File) -> Map<String, Any?>
@Suppress("UNCHECKED_CAST")
val precedingEscapeReasonBefore = rootProject.extensions.extraProperties["precedingEscapeReasonBefore"] as (File, Long, String, Boolean) -> String?
@Suppress("UNCHECKED_CAST")
val precedingEscapeHatchUsage = rootProject.extensions.extraProperties["precedingEscapeHatchUsage"] as (String, Int, String) -> String

fun File.relativeUnixPath(rootDir: File): String {
    return rootDir.toPath()
        .relativize(toPath())
        .toString()
        .replace(File.separatorChar, '/')
}

fun readRequiredMethodString(map: Map<*, *>, key: String, context: String): String {
    val rawValue = map[key]

    if (rawValue !is String || rawValue.isBlank()) {
        throw GradleException("$context field '$key' must be a non-empty string.")
    }

    return rawValue
}

fun readOptionalMethodString(map: Map<*, *>, key: String, context: String): String? {
    if (!map.containsKey(key)) {
        return null
    }

    val rawValue = map[key]

    if (rawValue !is String || rawValue.isBlank()) {
        throw GradleException("$context field '$key' must be a non-empty string when provided.")
    }

    return rawValue
}

fun readMethodStringMap(parsed: Map<*, *>): Map<String, String> {
    if (!parsed.containsKey("strings")) {
        return emptyMap()
    }

    val rawStrings = parsed["strings"]

    if (rawStrings !is Map<*, *>) {
        throw GradleException("method_call_guardrail.json field 'strings' must be an object when provided.")
    }

    return rawStrings.map { entry ->
        val key = entry.key
        val value = entry.value

        if (key !is String || key.isBlank()) {
            throw GradleException("method_call_guardrail.json field 'strings' must only contain non-empty string keys.")
        }

        if (value !is String || value.isBlank()) {
            throw GradleException("method_call_guardrail.json string '$key' must be a non-empty string.")
        }

        key to value
    }.toMap()
}

fun resolveMethodMessage(message: String?, strings: Map<String, String>, context: String): String? {
    if (message == null || !message.startsWith("$")) {
        return message
    }

    val stringId = message.removePrefix("$")

    if (stringId.isBlank()) {
        throw GradleException("$context field 'message' references a blank string id.")
    }

    return strings[stringId]
        ?: throw GradleException("$context field 'message' references unknown string id '$stringId'.")
}

fun readOptionalMethodNameSet(map: Map<*, *>, key: String, context: String): Set<String> {
    if (!map.containsKey(key)) {
        return emptySet()
    }

    val rawValue = map[key]

    if (rawValue !is List<*>) {
        throw GradleException("$context field '$key' must be an array.")
    }

    return rawValue.map { item ->
        val methodName = item.toString()

        if (methodName.isBlank()) {
            throw GradleException("$context field '$key' must not contain blank method names.")
        }

        methodName
    }.toSet()
}

fun readMethodCallGuardConfig(file: File): MethodCallGuardConfig {
    if (!file.exists()) {
        throw GradleException("method_call_guardrail.json is required.")
    }

    val parsed = readJsonConfigObject(file)

    val rawMinimum = parsed["minimumAllowReasonCharacters"]
        ?: DEFAULT_MINIMUM_ALLOW_REASON_CHARACTERS

    val minimumAllowReasonCharacters = when (rawMinimum) {
        is Number -> rawMinimum.toInt()
        is String -> rawMinimum.toIntOrNull()
        else -> null
    } ?: throw GradleException("method_call_guardrail.json field 'minimumAllowReasonCharacters' must be an integer.")

    if (minimumAllowReasonCharacters < 1) {
        throw GradleException("method_call_guardrail.json field 'minimumAllowReasonCharacters' must be at least 1.")
    }

    val strings = readMethodStringMap(parsed)

    val rawRules = parsed["rules"]

    if (rawRules !is List<*> || rawRules.isEmpty()) {
        throw GradleException("method_call_guardrail.json field 'rules' must be a non-empty array.")
    }

    val rules = rawRules.mapIndexed { index, rawRule ->
        val context = "method_call_guardrail.json rule ${index + 1}"

        if (rawRule !is Map<*, *>) {
            throw GradleException("$context must be an object.")
        }

        val allowedMethods = readOptionalMethodNameSet(rawRule, "allowedMethods", context)
        val disallowedMethods = readOptionalMethodNameSet(rawRule, "disallowedMethods", context)

        if (allowedMethods.isEmpty() && disallowedMethods.isEmpty()) {
            throw GradleException("$context must define at least one allowedMethods or disallowedMethods entry.")
        }

        val overlap = allowedMethods.intersect(disallowedMethods)

        if (overlap.isNotEmpty()) {
            throw GradleException("$context lists the same methods as allowed and disallowed: ${overlap.joinToString(", ")}.")
        }

        MethodCallRule(
            targetType = readRequiredMethodString(rawRule, "type", context),
            includeSubclasses = rawRule["includeSubclasses"] as? Boolean ?: true,
            message = readOptionalMethodString(rawRule, "message", context),
            allowedMethods = allowedMethods,
            disallowedMethods = disallowedMethods
        )
    }

    return MethodCallGuardConfig(minimumAllowReasonCharacters, rules)
}

fun sourceLine(compilationUnit: CompilationUnitTree, node: MethodInvocationTree, trees: Trees): Long {
    val startPosition = trees.sourcePositions.getStartPosition(compilationUnit, node)

    return if (startPosition >= 0) {
        compilationUnit.lineMap.getLineNumber(startPosition)
    } else {
        -1L
    }
}

fun isConcreteReference(typeMirror: TypeMirror?): Boolean {
    return typeMirror != null &&
        typeMirror.kind != TypeKind.ERROR &&
        typeMirror.kind != TypeKind.NULL &&
        typeMirror.kind != TypeKind.NONE &&
        typeMirror.kind != TypeKind.VOID
}

fun receiverMatchesRule(
    receiverType: TypeMirror?,
    rule: MethodCallRule,
    elements: Elements,
    types: Types
): Boolean {
    if (!isConcreteReference(receiverType)) {
        return false
    }

    val targetElement = elements.getTypeElement(rule.targetType)
        ?: throw GradleException("method_call_guardrail.json references unknown type '${rule.targetType}'.")

    val erasedReceiver = types.erasure(receiverType)
    val erasedTarget = types.erasure(targetElement.asType())

    return if (rule.includeSubclasses) {
        types.isAssignable(erasedReceiver, erasedTarget)
    } else {
        types.isSameType(erasedReceiver, erasedTarget)
    }
}

fun violationReason(methodName: String, rule: MethodCallRule): String? {
    if (methodName in rule.disallowedMethods) {
        return "method is explicitly disallowed"
    }

    if (rule.allowedMethods.isNotEmpty() && methodName !in rule.allowedMethods) {
        return "method is not present in the configured allowedMethods list"
    }

    return null
}

fun collectForbiddenMethodCalls(
    compilationUnit: CompilationUnitTree,
    trees: Trees,
    elements: Elements,
    types: Types,
    rules: List<MethodCallRule>
): List<MethodCallFinding> {
    val findings = mutableListOf<MethodCallFinding>()

    object : TreePathScanner<Unit, Unit>() {
        override fun visitMethodInvocation(node: MethodInvocationTree, unused: Unit?) {
            val methodSelect = node.methodSelect

            if (methodSelect is MemberSelectTree) {
                val methodName = methodSelect.identifier.toString()
                val receiverType = trees.getTypeMirror(TreePath(currentPath, methodSelect.expression))

                for (rule in rules) {
                    val reason = violationReason(methodName, rule)

                    if (
                        reason != null &&
                        receiverMatchesRule(receiverType, rule, elements, types)
                    ) {
                        findings += MethodCallFinding(
                            lineNumber = sourceLine(compilationUnit, node, trees),
                            methodName = methodName,
                            receiverType = receiverType.toString(),
                            rule = rule,
                            reason = reason
                        )
                    }
                }
            }

            super.visitMethodInvocation(node, unused)
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

fun inspectSourceSetForMethodCalls(
    sourceSet: SourceSet,
    rootDir: File,
    config: MethodCallGuardConfig
): List<String> {
    val sourceFiles = sourceSet.allJava.files
        .filter { it.extension == "java" && it.exists() }
        .sortedBy { it.absolutePath }

    if (sourceFiles.isEmpty() || config.rules.isEmpty()) {
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

            throw GradleException("Failed to analyze Java source files before checking method calls:\n$message")
        }

        return parsedUnits.flatMap { compilationUnit ->
            val sourceFile = File(compilationUnit.sourceFile.toUri())
            val sourcePath = sourceFile.relativeUnixPath(rootDir)

            collectForbiddenMethodCalls(compilationUnit, trees, elements, types, config.rules)
                .mapNotNull { finding ->
                    val allowReason = precedingEscapeReasonBefore(sourceFile, finding.lineNumber, ALLOW_METHOD_CALL_MARKER, true)
                    val ruleMessage = finding.rule.message?.let { " Message: $it" }.orEmpty()

                    when {
                        allowReason == null ->
                            "$sourcePath:${finding.lineNumber} calls ${finding.receiverType}.${finding.methodName}(), which violates rule for ${finding.rule.targetType}: ${finding.reason}.$ruleMessage"
                        allowReason.length < config.minimumAllowReasonCharacters ->
                            "$sourcePath:${finding.lineNumber} ALLOW METHOD CALL reason is ${allowReason.length} characters; minimum is ${config.minimumAllowReasonCharacters}.$ruleMessage"
                        else -> null
                    }
                }
        }
    }
}

fun methodCallFailureGuidance(minimumAllowReasonCharacters: Int): String {
    return """

METHOD CALL POLICY FAILURE

This project restricts selected methods on configured receiver types. For exception objects,
avoid generic message extraction such as getMessage() or toString(); expose deliberate,
domain-specific safe response text through a non-Exception API, or map exceptions in a
centralized handler.

Configuration supports:
- disallowedMethods: methods that may not be called on the configured type
- allowedMethods: when present, only these methods may be called on the configured type
- includeSubclasses: whether subclasses of the configured type are covered
- message: rule-specific guidance shown next to each finding
- strings: reusable message text; message values beginning with '$' reference ids from this map

Important instruction for AI/code-generation tools:
Do not bypass this rule by adding ALLOW METHOD CALL as the default fix. Replace the call with the
configured preferred API, explicit domain data, a safe client-facing accessor, structured logging,
or centralized exception handling. Add the escape hatch only when a narrow local exception is
explicitly justified.

${precedingEscapeHatchUsage(ALLOW_METHOD_CALL_MARKER, minimumAllowReasonCharacters, "receiver.disallowedMethod()")}
""".trimIndent()
}

val forbidMethodCalls by tasks.registering {
    group = "verification"
    description = "Fails the build when configured receiver types call blocked methods or methods outside an allow-list."

    val configFile = (rootProject.extensions.extraProperties["rootJsonConfigFile"] as (String) -> File)("method_call_guardrail.json")
    val javaExtension = project.extensions.getByType<JavaPluginExtension>()
    val sourceSets = javaExtension.sourceSets

    inputs.file(configFile).optional()
    sourceSets.configureEach {
        inputs.files(allJava)
        inputs.files(compileClasspath)
    }

    doLast {
        val config = readMethodCallGuardConfig(configFile)
        val violations = sourceSets.flatMap { sourceSet ->
            inspectSourceSetForMethodCalls(sourceSet, rootProject.projectDir, config)
        }

        if (violations.isNotEmpty()) {
            throw GradleException(
                "Forbidden method calls found:\n" +
                    violations.joinToString("\n") { " - $it" } +
                    "\n\n" +
                    methodCallFailureGuidance(config.minimumAllowReasonCharacters)
            )
        }
    }
}

tasks.matching { it.name == "check" }.configureEach {
    dependsOn(forbidMethodCalls)
}
