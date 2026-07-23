package org.owasp.untrust.buildgates.gradle

import org.gradle.api.GradleException
import org.gradle.api.Plugin
import org.gradle.api.Project
import java.io.File

class UntrustBuildGatesPlugin : Plugin<Project> {
    override fun apply(project: Project) {
        SCRIPT_NAMES.forEach { scriptName ->
            project.apply(mapOf("from" to materializeScript(project, scriptName)))
        }
    }

    private fun materializeScript(project: Project, scriptName: String): File {
        val resourcePath = "$SCRIPT_RESOURCE_ROOT/$scriptName"
        val targetFile = project.layout.buildDirectory
            .file("untrust-build-gates/scripts/$scriptName")
            .get()
            .asFile

        val resourceStream = javaClass.classLoader.getResourceAsStream(resourcePath)
            ?: throw GradleException("Untrust build gate script resource not found: $resourcePath")

        targetFile.parentFile.mkdirs()
        resourceStream.use { input ->
            targetFile.outputStream().use { output ->
                input.copyTo(output)
            }
        }

        return targetFile
    }

    private companion object {
        const val SCRIPT_RESOURCE_ROOT = "org/owasp/untrust/buildgates/scripts"

        val SCRIPT_NAMES = listOf(
            "json_config_reader.gradle.kts",
            "preceding_comment_as_escape_hatch.gradle.kts",
            "forbid-unsafe-imports.gradle.kts",
            "forbid-string-concat.gradle.kts",
            "forbid-local-catches.gradle.kts",
            "forbid-method-calls.gradle.kts",
            "forbid-null-literals.gradle.kts",
            "forbid-unvalidated-route-values.gradle.kts",
            "forbid-namespace-classes.gradle.kts",
            "forbid-validated-value-inheritance.gradle.kts",
            "forbid-direct-response-status-exception.gradle.kts",
            "require-controller-preauthorize.gradle.kts",
            "forbid-jooq-toctou.gradle.kts",
            "forbid-public-value-on-sensitive-types.gradle.kts"
        )
    }
}
