#include <jni.h>
#include <cstddef>
#include <sys/system_properties.h>

#ifndef _Included_Signature
#define _Included_Signature
#ifdef __cplusplus
extern "C" {
#endif

/// AES加密秘钥
unsigned char SECRET_KEY[] = "ZXphbmRyb2lk";

/// 指定类的路径，通过FindClass方法来找到对应的类
const char *className = "cn/ezandroid/ezprotect/lib/NativeApi";

jstring encrypt(JNIEnv *, jobject, jstring);

jstring decrypt(JNIEnv *, jobject, jstring);

jstring integrity(JNIEnv *, jobject);

/// 定义Native和Java方法映射关系
static JNINativeMethod jniMethods[] = {
        {"a", "(Ljava/lang/String;)Ljava/lang/String;", (void *) encrypt},
        {"b", "(Ljava/lang/String;)Ljava/lang/String;", (void *) decrypt},
        {"c", "()Ljava/lang/String;",                   (void *) integrity}
};

#ifdef __cplusplus
}
#endif
#endif
