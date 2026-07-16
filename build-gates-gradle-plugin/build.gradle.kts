plugins {
    `kotlin-dsl`
    `java-gradle-plugin`
    `maven-publish`
}

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(21)
    }
}

gradlePlugin {
    plugins {
        create("untrustBuildGates") {
            id = "org.owasp.untrust.build-gates"
            implementationClass = "org.owasp.untrust.buildgates.gradle.UntrustBuildGatesPlugin"
            displayName = "OWASP Untrust Build Gates"
            description = "Applies OWASP Untrust Java security and design build gates."
        }
    }
}

