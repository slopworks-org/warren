# Warren for Android

## Build

Use JDK 21, Go 1.27.3, Android SDK Platform 37, and NDK r28c
(`28.2.13676358`). Put the pinned Go installation on `PATH`. The Gradle
native build uses that local toolchain and rejects a different Go version.
The app supports Android 12 and later. Set `ANDROID_HOME` to the SDK
directory. Gradle uses the NDK in that SDK, or the directory named by
`WARREN_ANDROID_NDK`.

```sh
cd android
./gradlew :app:testDebugUnitTest :app:lintDebug :app:assembleDebug
(cd native && go test -race ./...)
```

The locally signed APK is `app/build/outputs/apk/debug/app-debug.apk`.
It contains arm64-v8a, armeabi-v7a and x86_64 native libraries. Set
`-PwarrenAbis=arm64-v8a` to build only for one ABI.
