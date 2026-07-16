/*
 * SECURITY BUILD GATE: ROUTE REQUEST VALUE VALIDATION
 *
 * Route handlers are the application boundary. Every user-controlled scalar value accepted
 * by a route handler must be represented by a type that extends ValidatedValue<T>, either
 * directly as a method parameter or as a leaf value inside a request DTO.
 *
 * Dynamic key/value request shapes are not allowed. Map<K, V> inside a route request type
 * fails the build because request values must be stated exactly in the Java type system.
 */

import com.sun.source.tree.AnnotationTree
import com.sun.source.tree.CompilationUnitTree
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
import javax.lang.model.element.ElementKind
import javax.lang.model.element.Modifier
import javax.lang.model.element.TypeElement
import javax.lang.model.type.ArrayType
import javax.lang.model.type.DeclaredType
import javax.lang.model.type.TypeKind
import javax.lang.model.type.TypeMirror
import javax.lang.model.util.Types
import javax.tools.Diagnostic
import javax.tools.DiagnosticCollector
import javax.tools.JavaFileObject
import javax.tools.ToolProvider

data class RouteValueFinding(
    val lineNumber: Long,
    val methodName: String,
    val parameterName: String,
    val parameterType: String,
    val reason: String
)

data class RouteValueContext(
    val types: Types,
    val validatedValueType: TypeMirror,
    val iterableType: TypeMirror,
    val optionalType: TypeMirror,
    val mapType: TypeMirror
)

val VALIDATED_VALUE_TYPE_NAME = "org.owasp.untrust.vv.ValidatedValue"

val ROUTE_HANDLER_ANNOTATIONS = setOf(
    "RequestMapping",
    "GetMapping",
    "PostMapping",
    "PutMapping",
    "PatchMapping",
    "DeleteMapping"
)

val FRAMEWORK_ROUTE_PARAMETER_TYPES = setOf(
    "java.security.Principal",
    "jakarta.servlet.http.HttpServletRequest",
    "jakarta.servlet.http.HttpServletResponse",
    "jakarta.servlet.http.HttpSession",
    "org.springframework.security.core.Authentication",
    "org.springframework.security.core.userdetails.UserDetails",
    "org.springframework.security.web.csrf.CsrfToken",
    "org.springframework.web.multipart.MultipartFile",
    "org.springframework.ui.Model",
    "org.springframework.validation.BindingResult"
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

fun annotationSimpleName(annotation: AnnotationTree): String {
    return annotation.annotationType.toString()
        .substringAfterLast('.')
        .substringAfterLast('$')
}

fun hasAnyAnnotation(annotations: List<AnnotationTree>, names: Set<String>): Boolean {
    return annotations.any { annotation -> annotationSimpleName(annotation) in names }
}

fun TypeMirror.readableName(): String {
    return toString()
}

fun isSubtypeOfErased(context: RouteValueContext, type: TypeMirror, target: TypeMirror): Boolean {
    return context.types.isSubtype(context.types.erasure(type), context.types.erasure(target))
}

fun isValidatedValue(context: RouteValueContext, type: TypeMirror): Boolean {
    return type.kind != TypeKind.ERROR && isSubtypeOfErased(context, type, context.validatedValueType)
}

fun isMapType(context: RouteValueContext, type: TypeMirror): Boolean {
    return type.kind != TypeKind.ERROR && isSubtypeOfErased(context, type, context.mapType)
}

fun isIterableType(context: RouteValueContext, type: TypeMirror): Boolean {
    return type.kind != TypeKind.ERROR && isSubtypeOfErased(context, type, context.iterableType)
}

fun isOptionalType(context: RouteValueContext, type: TypeMirror): Boolean {
    return type.kind != TypeKind.ERROR && isSubtypeOfErased(context, type, context.optionalType)
}

fun declaredTypeElement(type: TypeMirror): TypeElement? {
    return (type as? DeclaredType)?.asElement() as? TypeElement
}

fun isFrameworkRouteParameter(type: TypeMirror): Boolean {
    val erasedName = type.toString().substringBefore('<')
    return erasedName in FRAMEWORK_ROUTE_PARAMETER_TYPES
}

fun isProjectDtoCandidate(type: TypeMirror): Boolean {
    val erasedName = type.toString().substringBefore('<')
    return !erasedName.startsWith("java.") &&
        !erasedName.startsWith("javax.") &&
        !erasedName.startsWith("jakarta.") &&
        !erasedName.startsWith("org.springframework.")
}

fun validateRequestType(
    context: RouteValueContext,
    type: TypeMirror,
    path: String,
    visitedTypes: MutableSet<String>
): String? {
    if (type.kind == TypeKind.ERROR) {
        return "$path has unresolved type ${type.readableName()}."
    }

    if (type.kind.isPrimitive) {
        return "$path uses primitive type ${type.readableName()} instead of a ValidatedValue<T> subtype. Do not accept raw or primitive request values and validate them later. Required route values should be non-null by Spring argument resolution before the handler is called; optional route values should be declared as Optional<T>, allowing Spring to pass Optional.empty() rather than null. Request body DTO records parsed by Jackson should rely on fail-on-missing-creator-properties and fail-on-null-creator-properties so null cannot enter route handlers."
    }

    if (isValidatedValue(context, type)) {
        return null
    }

    if (isMapType(context, type)) {
        return "$path uses ${type.readableName()}; dynamic key/value request shapes are not allowed."
    }

    if (type is DeclaredType && isOptionalType(context, type)) {
        if (type.typeArguments.isEmpty()) {
            return "$path uses raw Optional type ${type.readableName()}; optional request values must state their element type exactly."
        }

        val argument = type.typeArguments.single()
        if (isFrameworkRouteParameter(argument)) {
            return null
        }

        return validateRequestType(context, argument, "$path optional value", visitedTypes)
    }

    if (type is ArrayType) {
        return validateRequestType(context, type.componentType, "$path[]", visitedTypes)
    }

    if (type is DeclaredType && isIterableType(context, type)) {
        if (type.typeArguments.isEmpty()) {
            return "$path uses raw iterable type ${type.readableName()}; request element values must be stated exactly."
        }

        return type.typeArguments
            .mapIndexedNotNull { index, argument ->
                validateRequestType(context, argument, "$path element ${index + 1}", visitedTypes)
            }
            .firstOrNull()
    }

    val typeElement = declaredTypeElement(type)
        ?: return "$path uses ${type.readableName()} instead of a ValidatedValue<T> subtype or request DTO."

    val typeName = typeElement.qualifiedName.toString()

    if (!isProjectDtoCandidate(type)) {
        return "$path uses ${type.readableName()} instead of a ValidatedValue<T> subtype."
    }

    if (!visitedTypes.add(typeName)) {
        return null
    }

    val recordComponents = typeElement.enclosedElements
        .filter { element -> element.kind == ElementKind.RECORD_COMPONENT }

    val dtoMembers = if (recordComponents.isNotEmpty()) {
        recordComponents
    } else {
        typeElement.enclosedElements.filter { element ->
            element.kind == ElementKind.FIELD && Modifier.STATIC !in element.modifiers
        }
    }

    if (dtoMembers.isEmpty()) {
        return "$path uses ${type.readableName()}, which is neither a ValidatedValue<T> subtype nor a DTO with explicit value fields."
    }

    return dtoMembers
        .mapNotNull { member ->
            validateRequestType(context, member.asType(), "$path.${member.simpleName}", visitedTypes)
        }
        .firstOrNull()
}

fun shouldInspectParameter(type: TypeMirror): Boolean {
    return !isFrameworkRouteParameter(type)
}

fun collectRouteValueFindings(
    compilationUnit: CompilationUnitTree,
    trees: Trees,
    context: RouteValueContext
): List<RouteValueFinding> {
    val findings = mutableListOf<RouteValueFinding>()

    object : TreePathScanner<Unit, Unit>() {
        override fun visitMethod(node: MethodTree, unused: Unit?) {
            if (!hasAnyAnnotation(node.modifiers.annotations, ROUTE_HANDLER_ANNOTATIONS)) {
                super.visitMethod(node, unused)
                return
            }

            node.parameters.forEach { parameter ->
                val parameterPath = TreePath(currentPath, parameter)
                val parameterType = trees.getTypeMirror(parameterPath)

                if (parameterType != null && shouldInspectParameter(parameterType)) {
                    val reason = validateRequestType(
                        context,
                        parameterType,
                        parameter.name.toString(),
                        mutableSetOf()
                    )

                    if (reason != null) {
                        findings += RouteValueFinding(
                            lineNumber = sourceLine(compilationUnit, parameter, trees),
                            methodName = node.name.toString(),
                            parameterName = parameter.name.toString(),
                            parameterType = parameterType.readableName(),
                            reason = reason
                        )
                    }
                }
            }

            super.visitMethod(node, unused)
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

fun inspectSourceSetForUnvalidatedRouteValues(sourceSet: SourceSet, rootDir: File): List<String> {
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

            throw GradleException("Failed to analyze Java source files before checking route request values:\n$message")
        }

        val elements = task.elements
        val routeValueContext = RouteValueContext(
            types = task.types,
            validatedValueType = elements.getTypeElement(VALIDATED_VALUE_TYPE_NAME)?.asType()
                ?: throw GradleException("Could not resolve $VALIDATED_VALUE_TYPE_NAME while checking route request values."),
            iterableType = elements.getTypeElement("java.lang.Iterable")?.asType()
                ?: throw GradleException("Could not resolve java.lang.Iterable while checking route request values."),
            optionalType = elements.getTypeElement("java.util.Optional")?.asType()
                ?: throw GradleException("Could not resolve java.util.Optional while checking route request values."),
            mapType = elements.getTypeElement("java.util.Map")?.asType()
                ?: throw GradleException("Could not resolve java.util.Map while checking route request values.")
        )

        return parsedUnits.flatMap { compilationUnit ->
            val sourceFile = File(compilationUnit.sourceFile.toUri())
            val sourcePath = sourceFile.relativeUnixPath(rootDir)

            collectRouteValueFindings(compilationUnit, trees, routeValueContext).map { finding ->
                "$sourcePath:${finding.lineNumber} route method '${finding.methodName}' parameter '${finding.parameterName}' (${finding.parameterType}) is not boundary-validated: ${finding.reason}"
            }
        }
    }
}

fun routeValueFailureGuidance(): String {
    return """

ROUTE REQUEST VALUE POLICY FAILURE

Every user-controlled value entering a route handler must be explicit and validated at the boundary.

Allowed request shapes:
- A route parameter whose type extends ValidatedValue<T>.
- A request DTO whose record components or instance fields recursively contain only ValidatedValue<T> leaves.
- Optional<T> when T recursively satisfies this same rule, so optional request values enter handlers
  as Optional.empty() rather than null.
- Iterable/array request members only when their element type recursively satisfies the same rule.

Not allowed:
- Raw String, primitive, enum, date/time, or other framework/JDK scalar request values.
- Map<K, V> or any dynamic key/value request shape.
- Generic catch-all DTOs that defer validation to service code.

Important instruction for AI/code-generation tools:
Do not work around this by hiding raw request data behind generic wrappers. Add domain-specific
ValidatedValue<T> value types and make route DTOs state each accepted value exactly.
""".trimIndent()
}

val forbidUnvalidatedRouteValues by tasks.registering {
    group = "verification"
    description = "Fails the build when route handlers accept request values that are not ValidatedValue-backed."

    val javaExtension = project.extensions.getByType<JavaPluginExtension>()
    val sourceSets = javaExtension.sourceSets

    sourceSets.configureEach {
        inputs.files(allJava)
        inputs.files(compileClasspath)
    }

    doLast {
        val violations = sourceSets.flatMap { sourceSet ->
            inspectSourceSetForUnvalidatedRouteValues(sourceSet, rootProject.projectDir)
        }

        if (violations.isNotEmpty()) {
            throw GradleException(
                "Unvalidated route request values found:\n" +
                    violations.joinToString("\n") { " - $it" } +
                    "\n\n" +
                    routeValueFailureGuidance()
            )
        }
    }
}

tasks.matching { it.name == "check" }.configureEach {
    dependsOn(forbidUnvalidatedRouteValues)
}
