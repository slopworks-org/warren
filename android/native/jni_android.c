#include <jni.h>
#include <stdint.h>
#include <stdlib.h>

extern char *warrenKeyPair(void);
extern int warrenOpen(int fd, uint32_t local, uint32_t control, uint16_t port);
extern void warrenSetForwarding(int enabled);
extern int warrenSocket(int mesh, int ipv6);
extern int warrenLanPort(void);
extern int warrenSetHub(char *config);
extern int warrenSetLAN(char *config, char *ips, int64_t deadline);
extern char *warrenDirectPaths(void);
extern void warrenClose(void);

#define BRIDGE(name) Java_org_slopworks_warren_vpn_WireGuard_##name

static jstring to_java(JNIEnv *env, char *s) {
    if (!s)
        return NULL;
    jstring result = (*env)->NewStringUTF(env, s);
    free(s);
    return result;
}

JNIEXPORT jstring JNICALL BRIDGE(keyPair)(JNIEnv *env, jobject self) {
    return to_java(env, warrenKeyPair());
}

JNIEXPORT jboolean JNICALL BRIDGE(open)(JNIEnv *env, jobject self, jint fd, jint local, jint control, jint port) {
    return warrenOpen(fd, (uint32_t)local, (uint32_t)control, (uint16_t)port);
}

JNIEXPORT void JNICALL BRIDGE(setForwarding)(JNIEnv *env, jobject self, jboolean enabled) {
    warrenSetForwarding(enabled);
}

JNIEXPORT jint JNICALL BRIDGE(socket)(JNIEnv *env, jobject self, jboolean mesh, jboolean ipv6) {
    return warrenSocket(mesh, ipv6);
}

JNIEXPORT jint JNICALL BRIDGE(lanPort)(JNIEnv *env, jobject self) {
    return warrenLanPort();
}

JNIEXPORT jboolean JNICALL BRIDGE(setHub)(JNIEnv *env, jobject self, jstring config) {
    const char *text = (*env)->GetStringUTFChars(env, config, NULL);
    if (!text)
        return JNI_FALSE;
    int ok = warrenSetHub((char *)text);
    (*env)->ReleaseStringUTFChars(env, config, text);
    return ok;
}

JNIEXPORT jboolean JNICALL BRIDGE(setLan)(JNIEnv *env, jobject self, jstring config, jstring ips, jlong deadline) {
    const char *text = (*env)->GetStringUTFChars(env, config, NULL);
    if (!text)
        return JNI_FALSE;
    const char *addresses = (*env)->GetStringUTFChars(env, ips, NULL);
    int ok = addresses ? warrenSetLAN((char *)text, (char *)addresses, (int64_t)deadline) : JNI_FALSE;
    if (addresses)
        (*env)->ReleaseStringUTFChars(env, ips, addresses);
    (*env)->ReleaseStringUTFChars(env, config, text);
    return ok;
}

JNIEXPORT jstring JNICALL BRIDGE(directPaths)(JNIEnv *env, jobject self) {
    return to_java(env, warrenDirectPaths());
}

JNIEXPORT void JNICALL BRIDGE(close)(JNIEnv *env, jobject self) {
    warrenClose();
}
