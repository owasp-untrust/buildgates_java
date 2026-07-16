# buildgates_java

Build metadata annotations and reusable Gradle build gates for OWASP Untrust Java projects.

This repository contains two related artifacts:

- `buildmetadata`: small Java marker annotations used by source code to document reviewed exceptions.
- `build-gates-gradle-plugin`: a Gradle plugin that applies the OWASP Untrust Java security and design gates.

Keeping these together is intentional. The annotations and the gates form one contract: source code marks a narrow exception, and the Gradle gates decide whether that exception is valid.

## Modules

```text
buildgates_java/
  buildmetadata/
    src/main/java/org/owasp/untrust/buildmetadata/
  build-gates-gradle-plugin/
    src/main/kotlin/org/owasp/untrust/buildgates/gradle/
    src/main/resources/org/owasp/untrust/buildgates/scripts/
```

## Requirements

- JDK 21
- Gradle wrapper included in this repository

Build everything:

```powershell
.\gradlew.bat build
```

On Unix-like shells:

```bash
./gradlew build
```

## Published Coordinates

Current Gradle metadata:

```kotlin
group = "org.owasp.untrust"
version = "0.1.0"
```

Expected Java annotation dependency:

```kotlin
dependencies {
    implementation("org.owasp.untrust:buildmetadata:0.1.0")
}
```

Expected Gradle plugin usage after publishing:

```kotlin
plugins {
    id("org.owasp.untrust.build-gates") version "0.1.0"
}
```

## Local Development Usage

Before publishing, consumers can use this repository as an included build.

For plugin resolution:

```kotlin
// settings.gradle.kts
pluginManagement {
    includeBuild("../BuildGates")
}
```

For dependency substitution of `org.owasp.untrust:buildmetadata`:

```kotlin
// settings.gradle.kts
includeBuild("../BuildGates")
```

Then a consumer build can apply:

```kotlin
plugins {
    java
    id("org.owasp.untrust.build-gates")
}
```

and depend on the annotations:

```kotlin
dependencies {
    implementation("org.owasp.untrust:buildmetadata:0.1.0")
}
```

## Java Marker Annotations

### `@StringConcatenationSafe`

Marks code where raw string concatenation is intentionally allowed and justified.

Use this when a build rule normally forbids string concatenation but a class or method has a narrow, reviewed reason to use it.

Example:

```java
import org.owasp.untrust.buildmetadata.StringConcatenationSafe;

@StringConcatenationSafe(
    "The values are fixed literals controlled by the developer, not user input."
)
public final class HardcodedMessageFactory {
    public String message(String suffix) {
        return "fixed-prefix-" + suffix;
    }
}
```

Good reasons explain the invariant:

```java
@StringConcatenationSafe("All concatenated values are developer-controlled Hardcoded descriptors.")
```

Weak reasons should not pass review:

```java
@StringConcatenationSafe("Needed.")
@StringConcatenationSafe("Safe.")
@StringConcatenationSafe("False positive.")
```

### `@NonFinalValidatedValue`

Marks a validated-value type that is intentionally non-final.

Validated value classes are usually expected to be final so validation cannot be bypassed through inheritance. Use this annotation only when inheritance is part of the design and the reason is explicit.

Example:

```java
import org.owasp.untrust.buildmetadata.NonFinalValidatedValue;

@NonFinalValidatedValue(
    "UUID-backed identifiers share the same parsing validation and may be specialized by domain."
)
public class UuidValue extends ValidatedValue<UUID, UuidValue.Traits> {
    // ...
}
```

## Gradle Build Gates Plugin

The plugin ID is:

```text
org.owasp.untrust.build-gates
```

The current plugin packages the existing `.gradle.kts` gates as resources and applies them in a stable order:

1. JSON config reader
2. preceding escape-hatch comment helpers
3. unsafe import gate
4. string concatenation gate
5. local catch gate
6. method-call gate
7. null literal gate
8. unvalidated route values gate
9. namespace class gate
10. validated value inheritance gate
11. jOOQ TOCTOU gate
12. public value on sensitive types gate

This wrapper keeps the existing gate logic intact while making the consumer build file small:

```kotlin
plugins {
    id("org.owasp.untrust.build-gates") version "0.1.0"
}
```

Instead of:

```kotlin
apply(from = "$rootDir/gradle/json_config_reader.gradle.kts")
apply(from = "$rootDir/gradle/preceding_comment_as_escape_hatch.gradle.kts")
apply(from = "$rootDir/gradle/forbid-unsafe-imports.gradle.kts")
apply(from = "$rootDir/gradle/forbid-string-concat.gradle.kts")
// ...
```

## Consumer Configuration Files

Some gates expect JSON configuration files in the consuming project root. Examples from current consumers include:

- `approved_import_alternatives.json`
- `allow_unsafe_imports.json`
- `string_concat_guardrail.json`
- `local_catch_guardrail.json`
- `method_call_guardrail.json`
- `validated_value_guardrail.json`

The plugin supplies the gate logic. The consuming application should still own its project-specific policy configuration.

## What Not To Do

- Do not copy-paste the gate scripts into every consuming repository once the plugin is available.
- Do not use `apply(from = "https://...")`; remote script application is hard to review and pin safely.
- Do not put application-specific policy JSON into this repository unless it is meant to be a reusable default.
- Do not use marker annotations to suppress a gate without an actionable security explanation.
- Do not split the annotations and gate plugin into unrelated release lifecycles unless there is a strong reason; version skew would make the contract harder to reason about.
- Do not treat these gates as runtime security controls. They are build-time enforcement and review aids.

## Repository Notes

This repository is intended to become:

```text
https://github.com/owasp-untrust/buildgates_java
```

Dependency order for the generated Java libraries:

1. `buildgates_java`
2. `valuedescriptor_java`
3. `vv_java`

Publish this repository first.

