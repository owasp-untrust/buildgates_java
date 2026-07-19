import groovy.json.JsonSlurper
import org.gradle.api.GradleException
import java.io.File

fun jsonConfigPath(rawPath: String, baseDir: File): File {
    val file = File(rawPath)
    return if (file.isAbsolute) file else File(baseDir, rawPath)
}

fun rootJsonConfigFile(fileName: String): File {
    val localFile = rootProject.file(fileName)
    if (localFile.exists()) {
        return localFile
    }

    val parentFile = rootProject.rootDir.parentFile?.resolve(fileName)
    return parentFile ?: localFile
}

fun jsonConfigContext(file: File): String {
    return file.relativeToOrSelf(rootProject.rootDir).path.replace(File.separatorChar, '/')
}

fun deepMergeJsonConfig(base: Map<String, Any?>, override: Map<String, Any?>): Map<String, Any?> {
    val merged = base.toMutableMap()

    override.forEach { (key, value) ->
        val baseValue = merged[key]

        merged[key] = if (baseValue is Map<*, *> && value is Map<*, *>) {
            @Suppress("UNCHECKED_CAST")
            deepMergeJsonConfig(baseValue as Map<String, Any?>, value as Map<String, Any?>)
        } else {
            value
        }
    }

    return merged
}

fun readJsonConfigStrings(config: Map<String, Any?>, sourceFile: File): Map<String, String> {
    val rawStrings = config["strings"] ?: return emptyMap()

    if (rawStrings !is Map<*, *>) {
        throw GradleException("${jsonConfigContext(sourceFile)} field 'strings' must be an object when provided.")
    }

    return rawStrings.map { entry ->
        val key = entry.key
        val value = entry.value

        if (key !is String || key.isBlank()) {
            throw GradleException("${jsonConfigContext(sourceFile)} field 'strings' must only contain non-empty string keys.")
        }

        if (value !is String || value.isBlank()) {
            throw GradleException("${jsonConfigContext(sourceFile)} string '$key' must be a non-empty string.")
        }

        key to value
    }.toMap()
}

fun resolveJsonConfigStringReference(
    value: String,
    strings: Map<String, String>,
    sourceFile: File,
    stringStack: List<String> = emptyList()
): String {
    if (!value.startsWith("$")) {
        return value
    }

    if (value.startsWith("$$")) {
        return value.drop(1)
    }

    val stringId = value.drop(1)

    if (stringId.isBlank()) {
        throw GradleException("${jsonConfigContext(sourceFile)} contains a blank string reference.")
    }

    if (stringId in stringStack) {
        val cycle = (stringStack + stringId).joinToString(" -> ")
        throw GradleException("${jsonConfigContext(sourceFile)} contains a string reference cycle: $cycle")
    }

    val referencedValue = strings[stringId]
        ?: throw GradleException("${jsonConfigContext(sourceFile)} references unknown string id '$stringId'.")

    return resolveJsonConfigStringReference(referencedValue, strings, sourceFile, stringStack + stringId)
}

fun resolveJsonConfigStringReferences(value: Any?, strings: Map<String, String>, sourceFile: File): Any? {
    return when (value) {
        is String -> resolveJsonConfigStringReference(value, strings, sourceFile)
        is Map<*, *> -> value.map { entry ->
            val key = entry.key

            if (key !is String || key.isBlank()) {
                throw GradleException("${jsonConfigContext(sourceFile)} JSON config object keys must be non-empty strings.")
            }

            key to resolveJsonConfigStringReferences(entry.value, strings, sourceFile)
        }.toMap()
        is List<*> -> value.map { item -> resolveJsonConfigStringReferences(item, strings, sourceFile) }
        else -> value
    }
}

fun normalizeJsonConfigValue(value: Any?, baseDir: File, includeStack: List<File>): Any? {
    return when (value) {
        is Map<*, *> -> resolveJsonConfigIncludes(value, baseDir, includeStack)
        is List<*> -> value.map { item -> normalizeJsonConfigValue(item, baseDir, includeStack) }
        else -> value
    }
}

fun resolveJsonConfigIncludes(rawMap: Map<*, *>, baseDir: File, includeStack: List<File>): Map<String, Any?> {
    val includeValue = rawMap["include"]
    val includedConfig = when (includeValue) {
        null -> emptyMap()
        is List<*> -> includeValue.fold(emptyMap<String, Any?>()) { mergedIncludes, rawIncludePath ->
            if (rawIncludePath !is String || rawIncludePath.isBlank()) {
                throw GradleException("JSON config field 'include' must contain only non-empty string paths.")
            }

            val includeFile = jsonConfigPath(rawIncludePath, baseDir)
            deepMergeJsonConfig(mergedIncludes, readJsonConfigObject(includeFile, includeStack))
        }
        else -> throw GradleException("JSON config field 'include' must be an array of paths.")
    }

    val currentConfig = rawMap
        .filterKeys { key -> key != "include" }
        .map { (key, value) ->
            if (key !is String || key.isBlank()) {
                throw GradleException("JSON config object keys must be non-empty strings.")
            }

            key to normalizeJsonConfigValue(value, baseDir, includeStack)
        }
        .toMap()

    return deepMergeJsonConfig(includedConfig, currentConfig)
}

fun readJsonConfigObject(file: File, includeStack: List<File> = emptyList()): Map<String, Any?> {
    if (!file.exists()) {
        throw GradleException("${jsonConfigContext(file)} is required.")
    }

    val canonicalFile = file.canonicalFile

    if (canonicalFile in includeStack) {
        val cycle = (includeStack + canonicalFile)
            .joinToString(" -> ") { jsonConfigContext(it) }

        throw GradleException("JSON config include cycle detected: $cycle")
    }

    val parsed = JsonSlurper().parse(canonicalFile)

    if (parsed !is Map<*, *>) {
        throw GradleException("${jsonConfigContext(file)} must contain a JSON object.")
    }

    val mergedConfig = resolveJsonConfigIncludes(parsed, canonicalFile.parentFile, includeStack + canonicalFile)
    val strings = readJsonConfigStrings(mergedConfig, canonicalFile)

    @Suppress("UNCHECKED_CAST")
    return resolveJsonConfigStringReferences(mergedConfig, strings, canonicalFile) as Map<String, Any?>
}

rootProject.extensions.extraProperties["readJsonConfigObject"] = { file: File ->
    readJsonConfigObject(file)
}
rootProject.extensions.extraProperties["rootJsonConfigFile"] = { fileName: String ->
    rootJsonConfigFile(fileName)
}
