plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.plugin.compose")
}

val nativeDir = rootProject.layout.projectDirectory.dir("native")
val ndkVersionPinned = "28.2.13676358"
val goVersionPinned = "go1.27.3"
val abiTargets = mapOf(
    "arm64-v8a" to ("arm64" to "aarch64-linux-android"),
    "armeabi-v7a" to ("arm" to "armv7a-linux-androideabi"),
    "x86_64" to ("amd64" to "x86_64-linux-android"),
)
val selectedAbis = providers.gradleProperty("warrenAbis").orNull?.split(',') ?: abiTargets.keys.toList()
require(selectedAbis.isNotEmpty() && selectedAbis.all { it in abiTargets }) { "Unsupported Warren ABI" }

val goOnPath = providers.environmentVariable("PATH").orElse("").map { path ->
    val name = if (File.separatorChar == '\\') "go.exe" else "go"
    path.split(File.pathSeparatorChar).asSequence()
        .filter(String::isNotEmpty)
        .map { File(it, name) }
        .firstOrNull { it.isFile && it.canExecute() }
        ?.absoluteFile ?: error("Install $goVersionPinned and add its bin directory to PATH.")
}
val goToolchain = goOnPath.flatMap { executable ->
    providers.exec {
        workingDir(nativeDir)
        environment("GOTOOLCHAIN", "local")
        commandLine(executable, "env", "GOVERSION", "GOTOOLDIR")
    }.standardOutput.asText
}.map { output ->
    val goEnvironment = output.trimEnd().lines()
    val version = goEnvironment.first()
    require(version == goVersionPinned) {
        "Warren Android requires $goVersionPinned on PATH, but found ${version.ifBlank { "an unknown version" }}."
    }
    version to File(goEnvironment[1])
}

android {
    namespace = "org.slopworks.warren"
    compileSdk = 37
    ndkVersion = ndkVersionPinned
    ndkPath = providers.environmentVariable("WARREN_ANDROID_NDK").orNull

    defaultConfig {
        applicationId = "org.slopworks.warren"
        minSdk = 31
        // API 36 retains the standard INTERNET permission for LAN sockets.
        targetSdk = 36
        versionCode = 1
        versionName = "0.3.1"
        ndk { abiFilters.addAll(selectedAbis) }
    }
    buildFeatures {
        compose = true
        buildConfig = true
    }
}

kotlin {
    jvmToolchain(21)
}

androidComponents {
    val sdk = sdkComponents.sdkDirectory
    onVariants { variant ->
        val native = tasks.register<BuildWireGuard>("build"+variant.name.replaceFirstChar(Char::uppercaseChar)+"WireGuard") {
            sources.set(nativeDir)
            output.set(layout.buildDirectory.dir("generated/wireguard/${variant.name}"))
            abis.set(selectedAbis)
            targets.set(abiTargets.mapValues { (_, target) -> "${target.first}:${target.second}" })
            ndkRevision.set(ndkVersionPinned)
            goExecutable.set(layout.file(goOnPath))
            goVersion.set(goToolchain.map { it.first })
            goTools.set(layout.dir(goToolchain.map { it.second }))
            ndk.set(layout.dir(providers.environmentVariable("WARREN_ANDROID_NDK").map { file(it) }
                .orElse(sdk.map { it.dir("ndk/$ndkVersionPinned").asFile })))
        }
        variant.sources.jniLibs?.addGeneratedSourceDirectory(native, BuildWireGuard::output)
    }
}

abstract class BuildWireGuard @Inject constructor(
    private val exec: org.gradle.process.ExecOperations,
) : DefaultTask() {
    @get:InputDirectory @get:PathSensitive(PathSensitivity.RELATIVE)
    abstract val sources: DirectoryProperty
    @get:OutputDirectory abstract val output: DirectoryProperty
    @get:Input abstract val abis: ListProperty<String>
    @get:Input abstract val targets: MapProperty<String, String>
    @get:Internal abstract val ndk: DirectoryProperty
    @get:Input abstract val ndkRevision: Property<String>
    @get:InputFile @get:PathSensitive(PathSensitivity.ABSOLUTE)
    abstract val goExecutable: RegularFileProperty
    @get:Input abstract val goVersion: Property<String>
    @get:InputDirectory @get:PathSensitive(PathSensitivity.RELATIVE)
    abstract val goTools: DirectoryProperty

    @TaskAction
    fun compile() {
        val root = ndk.get().asFile
        val properties = root.resolve("source.properties")
        require(properties.isFile && properties.readLines().any { it == "Pkg.Revision = ${ndkRevision.get()}" }) {
            "Install Android NDK r28c or set WARREN_ANDROID_NDK to its directory."
        }
        val toolchain = root.resolve("toolchains/llvm/prebuilt").listFiles()?.singleOrNull { it.isDirectory }
            ?: error("Install Android NDK r28c or set WARREN_ANDROID_NDK to its directory.")
        val artifacts = output.get().asFile
        artifacts.deleteRecursively()
        for (abi in abis.get()) {
            val (goArch, compiler) = targets.get().getValue(abi).split(':')
            val abiDir = artifacts.resolve(abi).apply { mkdirs() }
            val library = abiDir.resolve("libwarrenwg.so")
            exec.exec {
                workingDir(sources.get())
                environment("GOTOOLCHAIN", "local")
                environment("GOOS", "android")
                environment("GOARCH", goArch)
                if (goArch == "arm") environment("GOARM", "7")
                environment("CGO_ENABLED", "1")
                environment("CC", toolchain.resolve("bin/${compiler}31-clang"))
                commandLine(goExecutable.get().asFile, "build", "-trimpath", "-buildmode=c-shared", "-ldflags=-s -w", "-o", library, ".")
            }
            abiDir.resolve("libwarrenwg.h").delete()
        }
    }
}

dependencies {
    implementation(platform("androidx.compose:compose-bom:2026.09.00"))
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.compose.foundation:foundation")
    implementation("androidx.compose.material3:material3:1.5.0-rc01")
    implementation("androidx.activity:activity-compose:1.13.0")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.11.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.11.0")
    implementation("androidx.camera:camera-camera2:1.5.3")
    implementation("androidx.camera:camera-lifecycle:1.5.3")
    implementation("androidx.camera:camera-view:1.5.3")
    implementation("com.google.mlkit:barcode-scanning:17.3.0")
    testImplementation("junit:junit:4.13.2")
}
