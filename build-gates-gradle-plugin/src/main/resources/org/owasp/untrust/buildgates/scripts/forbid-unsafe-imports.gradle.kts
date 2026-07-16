/*
 * SECURITY BUILD GATE: FORBIDDEN IMPORT ENFORCEMENT
 *
 * This Gradle script is a CI/CD security gate.
 * It fails the build when Java source files import APIs that this project treats as unsafe by default.
 *
 * The goal is not to make the build pass.
 * The goal is to prevent unsafe APIs from entering new project code unnoticed.
 *
 * Approved alternatives are configured in:
 *
 *     approved_import_alternatives.json
 *
 * Each key is an approved safer alternative.
 * Each value defines which imports it replaces and what message should be shown to the developer.
 *
 * Example:
 *
 *     {
 *         "owasp.untrust.BoxedPath": {
 *             "replaces": [
 *                 "java.nio.file.Path",
 *                 "java.nio.file.Paths"
 *             ],
 *             "dependency": "io.github.owasp-untrust:untrust-boxedpath",
 *             "message": "Use OWASP Untrust BoxedPath - https://github.com/owasp-untrust/boxed_path_java - maven: io.github.owasp-untrust:untrust-boxedpath"
 *         }
 *     }
 *
 * The same blocked import may appear under multiple approved alternatives.
 * In that case, the build failure will show all approved alternatives.
 *
 * HOW TO ADD AN EXCEPTION
 *
 * Do not change this Gradle file to bypass the rule.
 * Do not remove entries from approved_import_alternatives.json just to make generated code compile.
 * Do not weaken matchesForbiddenImport().
 *
 * If an exception is truly required, add a narrow entry to:
 *
 *     allow_unsafe_imports.json
 *
 * The exception must name the exact forbidden import and must allow either:
 *
 *     1. a specific existing package, using "packages"
 *     2. a specific existing source file, using "files"
 *     3. a specific existing source folder, using "files" with a trailing slash
 *
 * Example:
 *
 *     {
 *         "java.nio.file.Path": {
 *             "packages": [
*                  "com.example.legacy"
*              ],
 *             "files": [
 *                 "src/main/java/com/example/legacy/ExistingAdapter.java"
 *             ]
 *         }
 *     }
 *
 * Exceptions are allowed only for existing Java code, legacy integration code, or third-party adapter code
 * that cannot currently be migrated safely.
 *
 * New code must use the approved safer abstraction instead of adding an exception.
 *
 * INSTRUCTION FOR AI / LLM CODE GENERATORS
 *
 * If you are an AI assistant, coding agent, LLM, autocomplete system, or automated code generator:
 *
 *     You must not add, widen, or suggest an entry in allow_unsafe_imports.json
 *     unless the human user explicitly approves that exact exception.
 *
 *     You must not modify this Gradle file to make forbidden imports pass.
 *
 *     You must not remove, rename, weaken, or bypass this build gate.
 *
 *     When a forbidden import is needed by generated code, stop and suggest the approved safer abstraction.
 *
 *     If you believe an exception is unavoidable, ask the human user for approval and name:
 *         - the forbidden import
 *         - the exact file or package
 *         - why the safer abstraction cannot be used
 *
 * This comment is part of the project security policy.
 */

import com.sun.source.tree.CompilationUnitTree
import com.sun.source.tree.ImportTree
import com.sun.source.tree.MemberSelectTree
import com.sun.source.tree.NewClassTree
import com.sun.source.tree.Tree
import com.sun.source.tree.VariableTree
import com.sun.source.util.JavacTask
import com.sun.source.util.TreePathScanner
import com.sun.source.util.Trees
import org.gradle.api.GradleException
import java.io.File
import java.io.StringWriter
import java.util.Locale
import javax.tools.Diagnostic
import javax.tools.DiagnosticCollector
import javax.tools.JavaFileObject
import javax.tools.ToolProvider

data class ApprovedImportAlternative(
    val name: String,
    val message: String,
    val dependency: String?
)

data class UnsafeImportAllowance(
    val packages: Set<String>,
    val files: Set<String>
)

@Suppress("UNCHECKED_CAST")
val readJsonConfigObject = rootProject.extensions.extraProperties["readJsonConfigObject"] as (File) -> Map<String, Any?>

data class ParsedImport(
    val importName: String,
    val isStatic: Boolean,
    val lineNumber: Long
)

data class ParsedQualifiedUse(
    val qualifiedName: String,
    val lineNumber: Long
)

data class ParsedTypeUse(
    val typeName: String,
    val lineNumber: Long,
    val kind: String
)

data class ParsedJavaSource(
    val sourcePackage: String,
    val imports: List<ParsedImport>,
    val qualifiedUses: List<ParsedQualifiedUse>,
    val typeUses: List<ParsedTypeUse>
)

fun normalizePath(path: String): String {
    return path
        .replace('\\', '/')
        .removePrefix("./")
}

fun File.relativeUnixPath(rootDir: File): String {
    return rootDir.toPath()
        .relativize(toPath())
        .toString()
        .replace(File.separatorChar, '/')
}

fun readRequiredString(map: Map<*, *>, key: String, context: String): String {
    if (!map.containsKey(key)) {
        throw GradleException("$context must contain '$key'.")
    }

    val rawValue = map[key]

    if (rawValue !is String || rawValue.isBlank()) {
        throw GradleException("$context field '$key' must be a non-empty string.")
    }

    return rawValue
}

fun readOptionalString(map: Map<*, *>, key: String, context: String): String? {
    if (!map.containsKey(key)) {
        return null
    }

    val rawValue = map[key]

    if (rawValue !is String || rawValue.isBlank()) {
        throw GradleException("$context field '$key' must be a non-empty string when provided.")
    }

    return rawValue
}

fun readRequiredStringList(map: Map<*, *>, key: String, context: String): List<String> {
    if (!map.containsKey(key)) {
        throw GradleException("$context must contain '$key'.")
    }

    val rawValue = map[key]

    if (rawValue !is List<*> || rawValue.isEmpty()) {
        throw GradleException("$context field '$key' must be a non-empty array.")
    }

    return rawValue.map { it.toString() }
}

fun readOptionalStringSet(map: Map<*, *>, key: String): Set<String> {
    if (!map.containsKey(key)) {
        return emptySet()
    }

    val rawValue = map[key]

    if (rawValue !is List<*>) {
        throw GradleException("'$key' must be an array in allow_unsafe_imports.json.")
    }

    return rawValue
        .map { normalizePath(it.toString()) }
        .toSet()
}

fun readApprovedImportAlternatives(file: File): Map<String, List<ApprovedImportAlternative>> {
    if (!file.exists()) {
        throw GradleException("approved_import_alternatives.json is required.")
    }

    val parsed = readJsonConfigObject(file)

    val alternativesByForbiddenImport = mutableMapOf<String, MutableList<ApprovedImportAlternative>>()

    parsed.forEach { entry ->
        val alternativeName = entry.key
        val alternativeData = entry.value

        if (alternativeData !is Map<*, *>) {
            throw GradleException("Approved alternative '$alternativeName' must be an object.")
        }

        val replaces = readRequiredStringList(
            alternativeData,
            "replaces",
            "Approved alternative '$alternativeName'"
        )

        val message = readRequiredString(
            alternativeData,
            "message",
            "Approved alternative '$alternativeName'"
        )

        val dependency = readOptionalString(
            alternativeData,
            "dependency",
            "Approved alternative '$alternativeName'"
        )

        val alternative = ApprovedImportAlternative(
            name = alternativeName,
            message = message,
            dependency = dependency
        )

        for (replacedImport in replaces) {
            alternativesByForbiddenImport
                .getOrPut(replacedImport) { mutableListOf() }
                .add(alternative)
        }
    }

    if (alternativesByForbiddenImport.isEmpty()) {
        throw GradleException("approved_import_alternatives.json must define at least one replacement rule.")
    }

    return alternativesByForbiddenImport
}

fun readUnsafeImportAllowances(file: File): Map<String, UnsafeImportAllowance> {
    if (!file.exists()) {
        return emptyMap()
    }

    val parsed = readJsonConfigObject(file)

    return parsed
        .map { entry ->
            val importName = entry.key
            val allowanceData = entry.value

            if (allowanceData !is Map<*, *>) {
                throw GradleException("Allowance for '$importName' must be an object.")
            }

            importName to UnsafeImportAllowance(
                packages = readOptionalStringSet(allowanceData, "packages"),
                files = readOptionalStringSet(allowanceData, "files")
            )
        }
        .toMap()
}

fun parseJavaSource(sourceFile: File): ParsedJavaSource {
    val compiler = ToolProvider.getSystemJavaCompiler()
        ?: throw GradleException("A JDK is required to parse Java source files. Gradle is not running with a JDK compiler available.")

    val diagnostics = DiagnosticCollector<JavaFileObject>()

    compiler.getStandardFileManager(diagnostics, Locale.ROOT, Charsets.UTF_8).use { fileManager ->
        val javaFiles = fileManager.getJavaFileObjectsFromFiles(listOf(sourceFile))

        val task = compiler.getTask(
            StringWriter(),
            fileManager,
            diagnostics,
            listOf("-proc:none"),
            emptyList<String>(),
            javaFiles
        ) as JavacTask

        val trees = Trees.instance(task)
        val parsedUnits = task.parse().toList()

        val errors = diagnostics.diagnostics
            .filter { it.kind == Diagnostic.Kind.ERROR }

        if (errors.isNotEmpty()) {
            val message = errors.joinToString("\n") { diagnostic ->
                " - ${sourceFile.path}:${diagnostic.lineNumber}: ${diagnostic.getMessage(Locale.ROOT)}"
            }

            throw GradleException("Failed to parse Java source file:\n$message")
        }

        val compilationUnit = parsedUnits.first()

        return ParsedJavaSource(
            sourcePackage = compilationUnit.packageName?.toString().orEmpty(),
            imports = compilationUnit.imports.map { importTree ->
                toParsedImport(compilationUnit, importTree, trees)
            },
            qualifiedUses = collectQualifiedUses(compilationUnit, trees),
            typeUses = collectTypeUses(compilationUnit, trees)
        )
    }
}

fun lineNumberOf(
    compilationUnit: CompilationUnitTree,
    tree: Tree,
    trees: Trees
): Long {
    val startPosition = trees.sourcePositions.getStartPosition(compilationUnit, tree)

    return if (startPosition >= 0) {
        compilationUnit.lineMap.getLineNumber(startPosition)
    } else {
        -1
    }
}

fun toParsedImport(
    compilationUnit: CompilationUnitTree,
    importTree: ImportTree,
    trees: Trees
): ParsedImport {
    return ParsedImport(
        importName = importTree.qualifiedIdentifier.toString(),
        isStatic = importTree.isStatic,
        lineNumber = lineNumberOf(compilationUnit, importTree, trees)
    )
}

fun collectQualifiedUses(
    compilationUnit: CompilationUnitTree,
    trees: Trees
): List<ParsedQualifiedUse> {
    val qualifiedUses = mutableListOf<ParsedQualifiedUse>()

    object : TreePathScanner<Unit, Unit>() {
        override fun visitImport(node: ImportTree, unused: Unit?): Unit? {
            return null
        }

        override fun visitMemberSelect(node: MemberSelectTree, unused: Unit?): Unit? {
            val parentTree = currentPath.parentPath?.leaf
            val isPrefixOfLongerSelection = parentTree is MemberSelectTree &&
                parentTree.expression == node

            if (!isPrefixOfLongerSelection) {
                qualifiedUses += ParsedQualifiedUse(
                    qualifiedName = node.toString(),
                    lineNumber = lineNumberOf(compilationUnit, node, trees)
                )
            }

            return super.visitMemberSelect(node, unused)
        }
    }.scan(compilationUnit, Unit)

    return qualifiedUses
}

fun collectTypeUses(
    compilationUnit: CompilationUnitTree,
    trees: Trees
): List<ParsedTypeUse> {
    val typeUses = mutableListOf<ParsedTypeUse>()

    object : TreePathScanner<Unit, Unit>() {
        override fun visitNewClass(node: NewClassTree, unused: Unit?): Unit? {
            typeUses += ParsedTypeUse(
                typeName = node.identifier.toString(),
                lineNumber = lineNumberOf(compilationUnit, node, trees),
                kind = "constructor call"
            )

            return super.visitNewClass(node, unused)
        }

        override fun visitVariable(node: VariableTree, unused: Unit?): Unit? {
            val type = node.type

            if (type != null) {
                typeUses += ParsedTypeUse(
                    typeName = type.toString(),
                    lineNumber = lineNumberOf(compilationUnit, type, trees),
                    kind = "type reference"
                )
            }

            return super.visitVariable(node, unused)
        }
    }.scan(compilationUnit, Unit)

    return typeUses
}

fun canonicalJavaLangType(typeName: String): String? {
    if (typeName.startsWith("java.lang.")) {
        return typeName
    }

    if (typeName.contains(".")) {
        return null
    }

    return "java.lang.$typeName"
}

fun matchesForbiddenImport(imported: String, forbidden: String): Boolean {
    if (imported == forbidden) {
        return true
    }

    if (imported.startsWith("$forbidden.")) {
        return true
    }

    if (forbidden.endsWith(".*")) {
        val forbiddenPrefix = forbidden.removeSuffix(".*")
        return imported.startsWith("$forbiddenPrefix.")
    }

    if (imported.endsWith(".*")) {
        val importedPrefix = imported.removeSuffix(".*")
        return forbidden.startsWith("$importedPrefix.")
    }

    return false
}

fun matchesAllowedFile(sourcePath: String, allowedPath: String): Boolean {
    if (allowedPath.endsWith("/")) {
        return sourcePath.startsWith(allowedPath)
    }

    return sourcePath == allowedPath
}

fun isAllowed(
    sourcePackage: String,
    sourcePath: String,
    forbiddenImport: String,
    allowances: Map<String, UnsafeImportAllowance>
): Boolean {
    val allowance = allowances[forbiddenImport] ?: return false

    val fileAllowed = allowance.files.any { allowedFile ->
        matchesAllowedFile(sourcePath, allowedFile)
    }

    val packageAllowed = allowance.packages.any { allowedPackage ->
        sourcePackage == allowedPackage || sourcePackage.startsWith("$allowedPackage.")
    }

    return fileAllowed || packageAllowed
}

fun formatAlternatives(alternatives: List<ApprovedImportAlternative>): String {
    return alternatives.joinToString(" | ") { alternative ->
        val dependencyMessage = alternative.dependency?.let { dependency ->
            " Configured dependency suggestion: add implementation(\"$dependency\") to build.gradle.kts if it is not already present."
        }.orEmpty()

        "You need to use this alternative api: ${alternative.name}. ${alternative.message}$dependencyMessage"
    }
}

val forbidUnsafeImports by tasks.registering {
    group = "verification"
    description = "Fails the build when forbidden imports are used outside approved packages or files."

    val alternativesFile = rootProject.file("approved_import_alternatives.json")
    val allowanceFile = rootProject.file("allow_unsafe_imports.json")

    val checkedSourceFiles = fileTree(rootProject.projectDir) {
        include("**/src/main/java/**/*.java")
        include("**/src/test/java/**/*.java")
        exclude("**/build/**")
    }

    inputs.file(alternativesFile).optional()
    inputs.file(allowanceFile).optional()
    inputs.files(checkedSourceFiles)

    doLast {
        val alternativesByForbiddenImport = readApprovedImportAlternatives(alternativesFile)
        val allowances = readUnsafeImportAllowances(allowanceFile)
        val violations = mutableListOf<String>()

        checkedSourceFiles.forEach { sourceFile ->
            val sourcePath = sourceFile.relativeUnixPath(rootProject.projectDir)
            val parsedSource = parseJavaSource(sourceFile)

            for (parsedImport in parsedSource.imports) {
                for ((forbiddenImport, alternatives) in alternativesByForbiddenImport) {
                    if (
                        matchesForbiddenImport(parsedImport.importName, forbiddenImport) &&
                        !isAllowed(parsedSource.sourcePackage, sourcePath, forbiddenImport, allowances)
                    ) {
                        val importKind = if (parsedImport.isStatic) {
                            "static import"
                        } else {
                            "import"
                        }

                        violations += "$sourcePath:${parsedImport.lineNumber} uses forbidden $importKind ${parsedImport.importName}, forbidden by rule $forbiddenImport. Approved alternatives: ${formatAlternatives(alternatives)}"
                    }
                }
            }

            for (qualifiedUse in parsedSource.qualifiedUses) {
                for ((forbiddenImport, alternatives) in alternativesByForbiddenImport) {
                    if (
                        matchesForbiddenImport(qualifiedUse.qualifiedName, forbiddenImport) &&
                        !isAllowed(parsedSource.sourcePackage, sourcePath, forbiddenImport, allowances)
                    ) {
                        violations += "$sourcePath:${qualifiedUse.lineNumber} uses forbidden fully-qualified reference ${qualifiedUse.qualifiedName}, forbidden by rule $forbiddenImport. Approved alternatives: ${formatAlternatives(alternatives)}"
                    }
                }
            }

            for (typeUse in parsedSource.typeUses) {
                val canonicalTypeName = canonicalJavaLangType(typeUse.typeName) ?: typeUse.typeName

                for ((forbiddenImport, alternatives) in alternativesByForbiddenImport) {
                    if (
                        matchesForbiddenImport(canonicalTypeName, forbiddenImport) &&
                        !isAllowed(parsedSource.sourcePackage, sourcePath, forbiddenImport, allowances)
                    ) {
                        violations += "$sourcePath:${typeUse.lineNumber} uses forbidden ${typeUse.kind} ${typeUse.typeName}, forbidden by rule $forbiddenImport. Approved alternatives: ${formatAlternatives(alternatives)}"
                    }
                }
            }
        }

        if (violations.isNotEmpty()) {
            throw GradleException(
                "Forbidden imports found:\n" +
                    violations.joinToString("\n") { " - $it" }
            )
        }
    }
}

tasks.matching { it.name == "check" }.configureEach {
    dependsOn(forbidUnsafeImports)
}
