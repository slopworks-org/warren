# Warren for Android

Warren uses Android's VPN consent flow and carries the routes provided by its
Warren hub. Internet traffic and DNS use the system's existing connection.
The device reports its actual LAN socket and physical subnet over the Warren
control channel. A server-authorized peer can take the direct path after an
authenticated round trip. Hub receive traffic works independently of the
current outbound path.

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

## Release APK

Each `v*` release on GitHub includes a signed universal `warren-android.apk`
and its checksum in `SHA256SUMS`. The APK uses the tag without the leading
`v` as its version name and the first-parent commit count as its version code.

The release workflow uses two GitHub Actions secrets. Set
`ANDROID_KEYSTORE_BASE64` to the base64-encoded release keystore containing a
single signing key, and `ANDROID_KEYSTORE_PASSWORD` to the password for both
the keystore and key. Keep a backup of the keystore and password so future
releases can update installed copies.

## Connection

The native bridge uses the same pinned upstream WireGuard Go revision as
WireGuard Android 1.0.20260102. The app links that engine against a single
Android VPN TUN descriptor. Separate hub and LAN WireGuard devices validate
incoming source addresses independently, while LAN lease and probe state
select the outbound device.

Use the server's Warren Android enrollment QR. The HTTPS origin in the QR
identifies the admin site. Android submits to `/agent/v1/register-resumable`
on TCP 80. The server can return the original signed receipt until the code
expires, while the device and its owner are active. If the server needs an
update, the app keeps the pending registration for retry. The returned
control endpoint is reached through WireGuard.

To enroll with a different code, open **Connection → Replace profile** and
confirm. The existing profile stays available until enrollment completes.
Once the new profile is saved, tap **Connect** to use it.
