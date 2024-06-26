/*
 *  Copyright (c) 2022 Microsoft Corporation
 *
 *  This program and the accompanying materials are made available under the
 *  terms of the Apache License, Version 2.0 which is available at
 *  https://www.apache.org/licenses/LICENSE-2.0
 *
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Contributors:
 *       Microsoft Corporation - initial API and implementation
 *
 */

plugins {
    `java-library`
}

val javaVersion: String by project
val defaultVersion: String by project
val annotationProcessorVersion: String by project
val metaModelVersion: String by project

var actualVersion: String = (project.findProperty("version") ?: defaultVersion) as String
if (actualVersion == "unspecified") {
    actualVersion = defaultVersion
}

buildscript {
    dependencies {
        val gradlePluginsGroup: String by project
        val gradlePluginsVersion: String by project
        classpath("${gradlePluginsGroup}.edc-build:${gradlePluginsGroup}.edc-build.gradle.plugin:${gradlePluginsVersion}")
    }
}

allprojects {
    val gradlePluginsGroup: String by project
    apply(plugin = "${gradlePluginsGroup}.edc-build")

    // configure which version of the annotation processor to use. defaults to the same version as the plugin
    configure<org.eclipse.edc.plugins.autodoc.AutodocExtension> {
        processorVersion.set(annotationProcessorVersion)
        outputDirectory.set(project.buildDir)
    }

    configure<org.eclipse.edc.plugins.edcbuild.extensions.BuildExtension> {
        versions {
            // override default dependency versions here
            projectVersion.set(actualVersion)
            metaModel.set(metaModelVersion)

        }
        pom {
            projectName.set(project.name)
            description.set("edc :: ${project.name}")
            projectUrl.set("https://github.com/ids-basecamp/edc-fork.git")
            scmConnection.set("git@github.com:ids-basecamp/edc-fork.git")
            scmUrl.set("https://github.com/ids-basecamp/edc-fork.git")
        }
        swagger {
            title.set((project.findProperty("apiTitle") ?: "EDC REST API") as String)
            description =
                (project.findProperty("apiDescription") ?: "EDC REST APIs - merged by OpenApiMerger") as String
            outputFilename.set(project.name)
            outputDirectory.set(file("${rootProject.projectDir.path}/resources/openapi/yaml"))
        }
        javaLanguageVersion.set(JavaLanguageVersion.of(javaVersion))
    }

    configure<CheckstyleExtension> {
        configFile = rootProject.file("resources/edc-checkstyle-config.xml")
        configDirectory.set(rootProject.file("resources"))
    }

    repositories {
        val gitHubUserName: String? by project
        val gitHubUserPassword: String? by project
        maven {
            url = uri("https://maven.pkg.github.com/ids-basecamp/ids-infomodel-java")
            credentials {
                username = gitHubUserName
                password = gitHubUserPassword
            }
        }
    }

    // EdcRuntimeExtension uses this to determine the runtime classpath of the module to run.
    tasks.register("printClasspath") {
        doLast {
            println(sourceSets["main"].runtimeClasspath.asPath)
        }
    }
}

// Dependency analysis active if property "dependency.analysis" is set. Possible values are <'fail'|'warn'|'ignore'>.
if (project.hasProperty("dependency.analysis")) {
    apply(plugin = "org.eclipse.edc.dependency-rules")
    configure<org.eclipse.edc.gradle.DependencyRulesPluginExtension> {
        severity.set(project.property("dependency.analysis").toString())
    }
}