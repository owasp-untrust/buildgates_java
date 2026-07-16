/*
 * DESIGN BUILD GATE: VALIDATED VALUE INHERITANCE ENFORCEMENT
 *
 * ValidatedValue subclasses should be leaf value types. Each value class should inherit directly
 * from ValidatedValue and own the Traits class that defines its validation behavior.
 *
 * Escape hatch:
 *
 *     // VALIDATED VALUE INHERITANCE REASON: <specific justification>
 *     class ...
 *
 *     // INTENTIONALLY EXPOSE UNCHECKED: <specific justification>
 *     return exposeUnchecked();
 *
 * The same guard applies to both unusual ValidatedValue inheritance and an owned Traits class
 * that intentionally inherits from a traits base outside package org.owasp.untrust.vv.
 */

import com.sun.source.tree.ClassTree
import com.sun.source.tree.CompilationUnitTree
import com.sun.source.tree.ExpressionTree
import com.sun.source.tree.MethodInvocationTree
import com.sun.source.tree.MethodTree
import com.sun.source.tree.ParenthesizedTree
import com.sun.source.tree.ReturnTree
import com.sun.source.tree.Tree
import com.sun.source.tree.TypeCastTree
import com.sun.source.util.JavacTask
import com.sun.source.util.TreePathScanner
import com.sun.source.util.TreeScanner
import com.sun.source.util.Trees
import groovy.json.JsonSlurper
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

data class ValidatedValueClassInfo(
    val qualifiedName: String,
    val simpleName: String,
    val packageName: String,
    val lineNumber: Long,
    val sourceFile: File,
    val sourcePath: String,
    val extendsText: String?,
    val implementsTexts: List<String>,
    val validatedValueTypeArgumentText: String?,
    val modifiers: Set<Modifier>,
    val nestedClasses: List<ValidatedValueNestedClassInfo>,
    val exposeUncheckedReturns: List<ValidatedValueExposeUncheckedReturn>,
    val allowReason: String?,
    val customValidationTraitsReason: String?
)

data class ValidatedValueNestedClassInfo(
    val simpleName: String,
    val extendsText: String?,
    val implementsTexts: List<String>
)

data class ValidatedValueExposeUncheckedReturn(
    val lineNumber: Long,
    val methodName: String,
    val allowReason: String?
)

data class ValidatedValueFinding(
    val lineNumber: Long,
    val className: String,
    val reason: String
)

data class ValidatedValueGuardConfig(
    val minimumCustomValidationTraitsReasonCharacters: Int,
    val minimumExposeUncheckedReasonCharacters: Int
)

val VALIDATED_VALUE_ALLOW_MARKER = "VALIDATED VALUE INHERITANCE REASON:"
val CUSTOM_VALIDATION_TRAITS_REASON_MARKER = "NEED FOR CUSTOM VALIDATION TRAITS:"
val INTENTIONALLY_EXPOSE_UNCHECKED_MARKER = "INTENTIONALLY EXPOSE UNCHECKED:"
val MINIMUM_VALIDATED_VALUE_ALLOW_REASON_CHARACTERS = 120
val VV_TRAIT_BASE_SIMPLE_NAMES = setOf(
    "BoundedAnyContentStringTraits",
    "BoundedValueTraits",
    "CustomValidationForRareCasesTraits",
    "EnumValidationTraits",
    "PrintableUnicodeStringTraits",
    "RareTraitsCaseWhereParsingIsTheWholeValidation",
    "RegexStringTraits",
    "ValidationTraits"
)
val VV_TRAIT_BASE_QUALIFIED_NAMES = VV_TRAIT_BASE_SIMPLE_NAMES
    .map { "org.owasp.untrust.vv.$it" }
    .toSet()
@Suppress("UNCHECKED_CAST")
val precedingEscapeReasonBefore = rootProject.extensions.extraProperties["precedingEscapeReasonBefore"] as (File, Long, String, Boolean) -> String?
@Suppress("UNCHECKED_CAST")
val precedingEscapeHatchUsage = rootProject.extensions.extraProperties["precedingEscapeHatchUsage"] as (String, Int, String) -> String

fun readValidatedValueGuardConfig(configFile: File): ValidatedValueGuardConfig {
    if (!configFile.exists()) {
        throw GradleException("validated_value_guardrail.json is required.")
    }

    val parsed = JsonSlurper().parse(configFile)
    if (parsed !is Map<*, *>) {
        throw GradleException("validated_value_guardrail.json must contain a JSON object.")
    }

    val rawMinimumCustomValidationTraitsReason = parsed["minimumCustomValidationTraitsReasonCharacters"]
    val minimumCustomValidationTraitsReason = when (rawMinimumCustomValidationTraitsReason) {
        is Number -> rawMinimumCustomValidationTraitsReason.toInt()
        is String -> rawMinimumCustomValidationTraitsReason.toIntOrNull()
        else -> null
    } ?: throw GradleException("validated_value_guardrail.json field 'minimumCustomValidationTraitsReasonCharacters' must be an integer.")

    if (minimumCustomValidationTraitsReason < 1) {
        throw GradleException("validated_value_guardrail.json field 'minimumCustomValidationTraitsReasonCharacters' must be at least 1.")
    }

    val rawMinimumExposeUncheckedReason = parsed["minimumExposeUncheckedReasonCharacters"]
    val minimumExposeUncheckedReason = when (rawMinimumExposeUncheckedReason) {
        is Number -> rawMinimumExposeUncheckedReason.toInt()
        is String -> rawMinimumExposeUncheckedReason.toIntOrNull()
        else -> null
    } ?: throw GradleException("validated_value_guardrail.json field 'minimumExposeUncheckedReasonCharacters' must be an integer.")

    if (minimumExposeUncheckedReason < 1) {
        throw GradleException("validated_value_guardrail.json field 'minimumExposeUncheckedReasonCharacters' must be at least 1.")
    }

    return ValidatedValueGuardConfig(minimumCustomValidationTraitsReason, minimumExposeUncheckedReason)
}

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

fun qualifiedClassName(packageName: String, classStack: List<String>, currentName: String): String {
    val nestedName = (classStack + currentName).joinToString(".")

    return if (packageName.isBlank()) {
        nestedName
    } else {
        "$packageName.$nestedName"
    }
}

fun allowReasonForClass(sourceFile: File, classLine: Long): String? {
    return precedingEscapeReasonBefore(sourceFile, classLine, VALIDATED_VALUE_ALLOW_MARKER, false)
}

fun customValidationTraitsReasonForClass(sourceFile: File, classLine: Long): String? {
    return precedingEscapeReasonBefore(sourceFile, classLine, CUSTOM_VALIDATION_TRAITS_REASON_MARKER, false)
}

fun exposeUncheckedReturnReason(sourceFile: File, returnLine: Long): String? {
    return precedingEscapeReasonBefore(sourceFile, returnLine, INTENTIONALLY_EXPOSE_UNCHECKED_MARKER, false)
}

fun collectValidatedValueClassInfo(
    compilationUnit: CompilationUnitTree,
    trees: Trees,
    rootDir: File
): List<ValidatedValueClassInfo> {
    val infos = mutableListOf<ValidatedValueClassInfo>()
    val packageName = compilationUnit.packageName?.toString().orEmpty()
    val sourceFile = File(compilationUnit.sourceFile.toUri())
    val sourcePath = sourceFile.relativeUnixPath(rootDir)
    val classStack = mutableListOf<String>()

    object : TreePathScanner<Unit, Unit>() {
        override fun visitClass(node: ClassTree, unused: Unit?) {
            val className = node.simpleName.toString()
            val lineNumber = sourceLine(compilationUnit, node, trees)
            val nestedClasses = node.members
                .filterIsInstance<ClassTree>()
                .map { nested ->
                    ValidatedValueNestedClassInfo(
                        simpleName = nested.simpleName.toString(),
                        extendsText = nested.extendsClause?.toString(),
                        implementsTexts = nested.implementsClause.map { it.toString() }
                    )
                }

            infos += ValidatedValueClassInfo(
                qualifiedName = qualifiedClassName(packageName, classStack, className),
                simpleName = className,
                packageName = packageName,
                lineNumber = lineNumber,
                sourceFile = sourceFile,
                sourcePath = sourcePath,
                extendsText = node.extendsClause?.toString(),
                implementsTexts = node.implementsClause.map { it.toString() },
                validatedValueTypeArgumentText = validatedValueTypeArgumentText(node.extendsClause?.toString()),
                modifiers = node.modifiers.flags,
                nestedClasses = nestedClasses,
                exposeUncheckedReturns = collectExposeUncheckedReturns(node, compilationUnit, trees, sourceFile),
                allowReason = allowReasonForClass(sourceFile, lineNumber),
                customValidationTraitsReason = customValidationTraitsReasonForClass(sourceFile, lineNumber)
            )

            classStack += className
            super.visitClass(node, unused)
            classStack.removeLast()
        }
    }.scan(compilationUnit, Unit)

    return infos
}

fun collectExposeUncheckedReturns(
    classTree: ClassTree,
    compilationUnit: CompilationUnitTree,
    trees: Trees,
    sourceFile: File
): List<ValidatedValueExposeUncheckedReturn> {
    return classTree.members
        .filterIsInstance<MethodTree>()
        .filter { it.body != null }
        .flatMap { method ->
            val findings = mutableListOf<ValidatedValueExposeUncheckedReturn>()

            object : TreeScanner<Unit, Unit>() {
                override fun visitClass(node: ClassTree, unused: Unit?) {
                    return
                }

                override fun visitReturn(node: ReturnTree, unused: Unit?) {
                    if (isExposeUncheckedInvocation(node.expression)) {
                        val lineNumber = sourceLine(compilationUnit, node, trees)
                        findings += ValidatedValueExposeUncheckedReturn(
                            lineNumber,
                            method.name.toString(),
                            exposeUncheckedReturnReason(sourceFile, lineNumber)
                        )
                    }
                    super.visitReturn(node, unused)
                }
            }.scan(method.body, Unit)

            findings
        }
}

fun isExposeUncheckedInvocation(expression: ExpressionTree?): Boolean {
    return when (expression) {
        is ParenthesizedTree -> isExposeUncheckedInvocation(expression.expression)
        is TypeCastTree -> isExposeUncheckedInvocation(expression.expression)
        is MethodInvocationTree -> expression.methodSelect.toString().substringAfterLast(".") == "exposeUnchecked"
        else -> false
    }
}

fun rawTypeName(typeText: String?): String? {
    if (typeText == null) {
        return null
    }

    return typeText.substringBefore("<").trim()
}

fun typeArguments(typeText: String?): List<String> {
    if (typeText == null) {
        return emptyList()
    }

    val start = typeText.indexOf('<')
    val end = typeText.lastIndexOf('>')
    if (start < 0 || end <= start) {
        return emptyList()
    }

    val arguments = mutableListOf<String>()
    val current = StringBuilder()
    var depth = 0

    for (character in typeText.substring(start + 1, end)) {
        when (character) {
            '<' -> {
                depth += 1
                current.append(character)
            }
            '>' -> {
                depth -= 1
                current.append(character)
            }
            ',' -> {
                if (depth == 0) {
                    arguments += current.toString().trim()
                    current.clear()
                } else {
                    current.append(character)
                }
            }
            else -> current.append(character)
        }
    }

    val finalArgument = current.toString().trim()
    if (finalArgument.isNotEmpty()) {
        arguments += finalArgument
    }

    return arguments
}

fun validatedValueTypeArgumentText(extendsText: String?): String? {
    val superType = rawTypeName(extendsText)
    if (superType != "ValidatedValue" && superType != "org.owasp.untrust.vv.ValidatedValue") {
        return null
    }

    return typeArguments(extendsText).firstOrNull()
}

fun simpleTypeName(typeText: String?): String? {
    return rawTypeName(typeText)?.substringAfterLast(".")
}

fun isOptionalType(typeText: String?): Boolean {
    val rawType = rawTypeName(typeText)
        ?: return false

    return rawType == "Optional" || rawType == "java.util.Optional"
}

fun isCustomValidationForRareCasesTraits(classInfo: ValidatedValueClassInfo): Boolean {
    val superType = rawTypeName(classInfo.extendsText)
        ?: return false

    return superType == "CustomValidationForRareCasesTraits" ||
        superType == "org.owasp.untrust.vv.CustomValidationForRareCasesTraits"
}

fun isDirectValidatedValue(classInfo: ValidatedValueClassInfo): Boolean {
    val superType = rawTypeName(classInfo.extendsText)
    return superType == "ValidatedValue" || superType == "org.owasp.untrust.vv.ValidatedValue"
}

fun isDirectValidationTraits(typeText: String?): Boolean {
    val rawType = rawTypeName(typeText)
        ?: return false

    return rawType == "ValidationTraits" || rawType == "org.owasp.untrust.vv.ValidationTraits"
}

fun resolveSuperInfo(
    classInfo: ValidatedValueClassInfo,
    classesByQualifiedName: Map<String, ValidatedValueClassInfo>,
    classesBySimpleName: Map<String, List<ValidatedValueClassInfo>>
): ValidatedValueClassInfo? {
    val superType = rawTypeName(classInfo.extendsText) ?: return null

    classesByQualifiedName[superType]?.let { return it }
    classesByQualifiedName["${classInfo.packageName}.$superType"]?.let { return it }

    val simpleName = superType.substringAfterLast(".")
    return classesBySimpleName[simpleName]?.singleOrNull()
}

fun inheritsFromValidatedValue(
    classInfo: ValidatedValueClassInfo,
    classesByQualifiedName: Map<String, ValidatedValueClassInfo>,
    classesBySimpleName: Map<String, List<ValidatedValueClassInfo>>,
    visited: Set<String> = emptySet()
): Boolean {
    if (classInfo.qualifiedName in visited) {
        return false
    }

    if (isDirectValidatedValue(classInfo)) {
        return true
    }

    val superInfo = resolveSuperInfo(classInfo, classesByQualifiedName, classesBySimpleName)
        ?: return false

    return inheritsFromValidatedValue(
        superInfo,
        classesByQualifiedName,
        classesBySimpleName,
        visited + classInfo.qualifiedName
    )
}

fun implementsOrInheritsValidationTraits(
    classInfo: ValidatedValueClassInfo,
    classesByQualifiedName: Map<String, ValidatedValueClassInfo>,
    classesBySimpleName: Map<String, List<ValidatedValueClassInfo>>,
    visited: Set<String> = emptySet()
): Boolean {
    if (classInfo.qualifiedName in visited) {
        return false
    }

    if (classInfo.implementsTexts.any(::isDirectValidationTraits)) {
        return true
    }

    val superInfo = resolveSuperInfo(classInfo, classesByQualifiedName, classesBySimpleName)
        ?: return false

    return implementsOrInheritsValidationTraits(
        superInfo,
        classesByQualifiedName,
        classesBySimpleName,
        visited + classInfo.qualifiedName
    )
}

fun hasOwnedVvTraitsClass(
    classInfo: ValidatedValueClassInfo,
    vvTraitSimpleNames: Set<String>,
    vvTraitQualifiedNames: Set<String>
): Boolean {
    val traitsClass = classInfo.nestedClasses.singleOrNull { it.simpleName == "Traits" }
        ?: return false

    val superType = rawTypeName(traitsClass.extendsText)
        ?: return false

    return superType in vvTraitQualifiedNames || simpleTypeName(superType) in vvTraitSimpleNames
}

fun allowReasonProblem(classInfo: ValidatedValueClassInfo): String? {
    val reason = classInfo.allowReason ?: return null

    return if (reason.length < MINIMUM_VALIDATED_VALUE_ALLOW_REASON_CHARACTERS) {
        "ALLOW reason is ${reason.length} characters; minimum is $MINIMUM_VALIDATED_VALUE_ALLOW_REASON_CHARACTERS."
    } else {
        null
    }
}

fun customValidationTraitsReasonProblem(classInfo: ValidatedValueClassInfo, config: ValidatedValueGuardConfig): String? {
    if (!isCustomValidationForRareCasesTraits(classInfo)) {
        return null
    }

    val reason = classInfo.customValidationTraitsReason
        ?: return "extends CustomValidationForRareCasesTraits without an immediately preceding $CUSTOM_VALIDATION_TRAITS_REASON_MARKER comment."

    return if (reason.length < config.minimumCustomValidationTraitsReasonCharacters) {
        "$CUSTOM_VALIDATION_TRAITS_REASON_MARKER reason is ${reason.length} characters; minimum is ${config.minimumCustomValidationTraitsReasonCharacters}."
    } else {
        null
    }
}

fun exposeUncheckedReturnProblem(returned: ValidatedValueExposeUncheckedReturn, config: ValidatedValueGuardConfig): String? {
    val reason = returned.allowReason
        ?: return "method ${returned.methodName}() returns exposeUnchecked(). Do not add convenience accessors that hide the explicit safety boundary; callers must call exposeUnchecked() at the point where they consciously leave the validated value wrapper."

    return if (reason.length < config.minimumExposeUncheckedReasonCharacters) {
        "$INTENTIONALLY_EXPOSE_UNCHECKED_MARKER reason is ${reason.length} characters; minimum is ${config.minimumExposeUncheckedReasonCharacters}."
    } else {
        null
    }
}

fun collectValidatedValueFindings(
    classInfos: List<ValidatedValueClassInfo>,
    config: ValidatedValueGuardConfig
): Map<String, List<ValidatedValueFinding>> {
    val classesByQualifiedName = classInfos.associateBy { it.qualifiedName }
    val classesBySimpleName = classInfos.groupBy { it.simpleName }
    val vvTraitInfos = classInfos
        .filter {
            it.packageName == "org.owasp.untrust.vv" &&
                implementsOrInheritsValidationTraits(it, classesByQualifiedName, classesBySimpleName)
        }
    val vvTraitSimpleNames = vvTraitInfos.map { it.simpleName }.toSet() + VV_TRAIT_BASE_SIMPLE_NAMES
    val vvTraitQualifiedNames = vvTraitInfos.map { it.qualifiedName }.toSet() + VV_TRAIT_BASE_QUALIFIED_NAMES

    return classInfos
        .mapNotNull { classInfo ->
            val customTraitsProblem = customValidationTraitsReasonProblem(classInfo, config)
            if (!inheritsFromValidatedValue(classInfo, classesByQualifiedName, classesBySimpleName)) {
                return@mapNotNull customTraitsProblem?.let { problem ->
                    classInfo.sourcePath to listOf(ValidatedValueFinding(classInfo.lineNumber, classInfo.qualifiedName, problem))
                }
            }

            val findings = mutableListOf<ValidatedValueFinding>()

            customTraitsProblem?.let { problem ->
                findings += ValidatedValueFinding(classInfo.lineNumber, classInfo.qualifiedName, problem)
            }

            allowReasonProblem(classInfo)?.let { problem ->
                findings += ValidatedValueFinding(classInfo.lineNumber, classInfo.qualifiedName, problem)
            }

            val hasValidAllow = classInfo.allowReason != null && allowReasonProblem(classInfo) == null

            if (!hasValidAllow) {
                if (!isDirectValidatedValue(classInfo)) {
                    findings += ValidatedValueFinding(
                        classInfo.lineNumber,
                        classInfo.qualifiedName,
                        "inherits from another ValidatedValue descendant instead of directly extending ValidatedValue."
                    )
                }

                if (Modifier.FINAL !in classInfo.modifiers) {
                    findings += ValidatedValueFinding(
                        classInfo.lineNumber,
                        classInfo.qualifiedName,
                        "is a ValidatedValue descendant but is not final."
                    )
                }

                if (isDirectValidatedValue(classInfo) && !hasOwnedVvTraitsClass(classInfo, vvTraitSimpleNames, vvTraitQualifiedNames)) {
                    findings += ValidatedValueFinding(
                        classInfo.lineNumber,
                        classInfo.qualifiedName,
                        "directly extends ValidatedValue but does not own a nested Traits class extending a traits class from package org.owasp.untrust.vv."
                    )
                }

                if (isDirectValidatedValue(classInfo) && isOptionalType(classInfo.validatedValueTypeArgumentText)) {
                    findings += ValidatedValueFinding(
                        classInfo.lineNumber,
                        classInfo.qualifiedName,
                        "uses ValidatedValue<${classInfo.validatedValueTypeArgumentText}, ...>. ValidatedValue must wrap the actual value type, not Optional<T>. Move Optional to the field in the request DTO or to the argument definition in the route handler, for example record SomethingRequest(Optional<${classInfo.simpleName}> value, Title title) or a route argument Optional<${classInfo.simpleName}> value."
                    )
                }

            }

            classInfo.exposeUncheckedReturns.forEach { returned ->
                exposeUncheckedReturnProblem(returned, config)?.let { problem ->
                    findings += ValidatedValueFinding(
                        returned.lineNumber,
                        classInfo.qualifiedName,
                        problem
                    )
                }
            }

            if (findings.isEmpty()) {
                null
            } else {
                classInfo.sourcePath to findings
            }
        }
        .groupBy({ it.first }, { it.second })
        .mapValues { (_, nestedFindings) -> nestedFindings.flatten() }
}

fun inspectSourceSetForValidatedValueInheritance(
    sourceSet: SourceSet,
    rootDir: File,
    config: ValidatedValueGuardConfig
): Map<String, List<ValidatedValueFinding>> {
    val sourceFiles = sourceSet.allJava.files
        .filter { it.extension == "java" && it.exists() }
        .sortedBy { it.absolutePath }

    if (sourceFiles.isEmpty()) {
        return emptyMap()
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

            throw GradleException("Failed to analyze Java source files before checking ValidatedValue inheritance:\n$message")
        }

        return collectValidatedValueFindings(parsedUnits.flatMap { compilationUnit ->
            collectValidatedValueClassInfo(compilationUnit, trees, rootDir)
        }, config)
    }
}

fun validatedValueInheritanceFailureGuidance(config: ValidatedValueGuardConfig): String {
    return """

VALIDATED VALUE INHERITANCE POLICY FAILURE

ValidatedValue classes must be leaf values:
- Extend ValidatedValue directly.
- Mark the value class final.
- Define an owned nested Traits class that extends one of the traits classes in package
  org.owasp.untrust.vv.
- Do not use Optional<T> as the ValidatedValue value type. The value class should validate
  the present value, while absence belongs at the boundary as Optional<ValueClass> on a DTO
  field or route handler argument, for example:
     record SomethingRequest(Optional<CommentId> commentId, Title title)
- Do not add methods that return exposeUnchecked(). That hides the safety boundary behind a
  harmless-looking accessor. Call exposeUnchecked() at the actual use site when raw access is
  intentionally needed.
- Avoid CustomValidationForRareCasesTraits unless the validation really cannot be expressed
  with the standard traits.

Do not create intermediate value base classes such as RequiredTextValue or OptionalTextValue
or inherit an owned Traits class from outside package org.owasp.untrust.vv unless a human
intentionally accepts that abstraction with an escape hatch comment.

The comment is for exceptional designs only: explain why direct ValidatedValue inheritance or
the existing vv traits are not suitable, and how the deeper inheritance or non-vv trait-base risk
is constrained.

${precedingEscapeHatchUsage(INTENTIONALLY_EXPOSE_UNCHECKED_MARKER, config.minimumExposeUncheckedReasonCharacters, "return exposeUnchecked();")}

${precedingEscapeHatchUsage(CUSTOM_VALIDATION_TRAITS_REASON_MARKER, config.minimumCustomValidationTraitsReasonCharacters, "static final class Traits extends CustomValidationForRareCasesTraits<Something> {")}

${precedingEscapeHatchUsage(VALIDATED_VALUE_ALLOW_MARKER, MINIMUM_VALIDATED_VALUE_ALLOW_REASON_CHARACTERS, "public final class Something extends ValidatedValue<String, Something.Traits> {")}
""".trimIndent()
}

val forbidValidatedValueInheritance by tasks.registering {
    group = "verification"
    description = "Fails the build when ValidatedValue descendants are not final direct values with owned vv traits."

    val javaExtension = project.extensions.getByType<JavaPluginExtension>()
    val sourceSets = javaExtension.sourceSets

    sourceSets.configureEach {
        inputs.files(allJava)
        inputs.files(compileClasspath)
    }
    inputs.file(rootProject.file("validated_value_guardrail.json"))

    doLast {
        val config = readValidatedValueGuardConfig(rootProject.file("validated_value_guardrail.json"))
        val findingsBySource = sourceSets
            .map { sourceSet -> inspectSourceSetForValidatedValueInheritance(sourceSet, rootProject.projectDir, config) }
            .fold(emptyMap<String, List<ValidatedValueFinding>>()) { acc, findings ->
                (acc.keys + findings.keys).associateWith { key ->
                    acc.getOrDefault(key, emptyList()) + findings.getOrDefault(key, emptyList())
                }
            }

        if (findingsBySource.isNotEmpty()) {
            val violations = findingsBySource
                .toSortedMap()
                .flatMap { (sourcePath, findings) ->
                    findings.sortedBy { it.lineNumber }.map { finding ->
                        "$sourcePath:${finding.lineNumber} ${finding.className} ${finding.reason}"
                    }
                }

            throw GradleException(
                "ValidatedValue inheritance violations found:\n" +
                    violations.joinToString("\n") { " - $it" } +
                    "\n\n" +
                    validatedValueInheritanceFailureGuidance(config)
            )
        }
    }
}

tasks.matching { it.name == "check" }.configureEach {
    dependsOn(forbidValidatedValueInheritance)
}
