#include <jni.h>
#include <cstdio>
#include <dirent.h>
#include <sys/ptrace.h>
#include <libgen.h>
#include "NativeApi.h"
#include "../util/MD5.h"
#include "../util/Logger.h"
#include "../util/Aes.h"

/// 使用pm命令获取真实的APK安装包路径
static const char *getRealAPKPath() {
    string cmd("/system/bin/pm path ");
#if defined( CORRECT_PACKAGE_NAME )
    cmd.append(CORRECT_PACKAGE_NAME);
#endif
    cmd.append(" | /system/bin/sed 's/package://'");
    FILE *fp;
    char *path = new char[1024];
    fp = popen(cmd.c_str(), "r");
    if (fp == nullptr) {
        return "";
    }
    int readCnt = 0;
    while (fgets(path, 1024, fp) != nullptr) {
        readCnt++;
    }
    pclose(fp);
    // 将换行符替换为\0，以便将其传递给fopen
    path[strcspn(path, "\n")] = 0;
    if (readCnt != 1) {
        return "";
    }
    return path;
}

static const char *getFileDir(const char *path) {
    // path一般为/data/app/xxx/base.apk
    return dirname(path);
}

static int getFileSize(const char *path) {
    FILE *fp = fopen(path, "rb");
    if (fp == nullptr) {
        return 0;
    }
    fseek(fp, 0L, SEEK_END);
    long size = ftell(fp);
    fclose(fp);
    return size;
}

/// 检测是否被动态调试
/// 1.通过ptrace自添加防止被调试器挂载来反调试
/// 2.通过系统提供的Debug.isDebuggerConnected()方法来进行判断
static bool checkDebug(JNIEnv *env) {
//    // 自添加似乎有兼容性问题？待测试
//    ptrace(PTRACE_TRACEME, 0, 0, 0);

    jclass vm_debug_clz = env->FindClass("android/os/Debug");
    jmethodID isDebuggerConnected = env->GetStaticMethodID(vm_debug_clz, "isDebuggerConnected", "()Z");
    if (isDebuggerConnected == nullptr) {
        return false;
    }
    return env->CallStaticBooleanMethod(vm_debug_clz, isDebuggerConnected);
}

char *strlwr(char *str) {
    char *origin = str;
    for (; *str != '\0'; str++)
        *str = (char) tolower(*str);
    return origin;
}

/// 检测是否被Xposed等框架注入
/// 已支持检测Xposed、Virtual Xposed、Cydia Substrate、Frida等
/// TODO 未来可增加对太极等更多框架的检测
static bool checkXposedOrCydia(JNIEnv *env) {
    const char *file_path = "/proc/self/maps";
    const char *xposed_lib = "xposed"; // Xposed、Virtual Xposed框架
    const char *substrate_lib = "substrate"; // Cydia Substrate框架
    const char *frida_lib = "frida"; // Frida框架
    FILE *fp = fopen(file_path, "r");
    if (fp != nullptr) {
        char line[1024] = {0};
        while (fgets(line, sizeof(line), fp) != nullptr) {
//            LOGE("%s", line);
            char *lwr = strlwr(line);
            if (strstr(lwr, xposed_lib) || strstr(lwr, substrate_lib) || strstr(lwr, frida_lib)) {
                return true;
            }
        }
        fclose(fp);
    }
    return false;
}

/// 获取sPackageManager对象
static jobject getPackageManager(JNIEnv *env) {
    jclass activity_thread_clz = env->FindClass("android/app/ActivityThread");
    if (activity_thread_clz == nullptr) {
        return nullptr;
    }
    jmethodID getPackageManager = env->GetStaticMethodID(activity_thread_clz, "getPackageManager", "()Landroid/content/pm/IPackageManager;");
    if (getPackageManager == nullptr) {
        return nullptr;
    }
    return env->CallStaticObjectMethod(activity_thread_clz, getPackageManager);
}

/// 检测PMS是否被Hook
/// 大部分一键去签名校验的工具（如MT管理器和NP管理器）都是通过Hook PMS来实现的，因此这里进行检测
static bool checkHookPMS(JNIEnv *env) {
    jobject pms = getPackageManager(env);
    jclass pms_clz = env->GetObjectClass(pms);
    if (pms_clz == nullptr) {
        return false;
    }
    jclass pms_parent_clz = env->GetSuperclass(pms_clz);
    if (pms_parent_clz == nullptr) {
        return false;
    }
    jclass proxyClass = env->FindClass("java/lang/reflect/Proxy");
    if (proxyClass == nullptr) {
        return false;
    }

//    jclass cls = env->FindClass("java/lang/Class");
//    jmethodID getName = env->GetMethodID(cls, "getName", "()Ljava/lang/String;");
//    auto cls_name = (jstring) env->CallObjectMethod(pms_clz, getName);
//    const char *cls_name_chars = env->GetStringUTFChars(cls_name, nullptr);
//    LOGI("cls_name : %s", cls_name_chars);

    if (env->IsAssignableFrom(pms_parent_clz, proxyClass)) {
        return true;
    }
    return false;
}

/// 获取Application对象
static jobject getApplication(JNIEnv *env) {
    jclass activity_thread_clz = env->FindClass("android/app/ActivityThread");
    if (activity_thread_clz == nullptr) {
        return nullptr;
    }
    jmethodID currentApplication = env->GetStaticMethodID(activity_thread_clz, "currentApplication", "()Landroid/app/Application;");
    if (currentApplication == nullptr) {
        return nullptr;
    }
    return env->CallStaticObjectMethod(activity_thread_clz, currentApplication);
}

/// 检测Application的className属性
/// 大部分一键去签名校验的工具（如MT管理器和NP管理器）都会通过修改入口Application类，并在修改后的Application类中添加各种破解代码来实现去签名校验，
/// 它们常常费了很大的劲比如Hook了PMS，同时为了防止你读取原包做文件完整性校验可能还进行了IO重定向，但偏偏忽视了对Application类名的隐藏，因此进行检测
static bool checkApplicationName(JNIEnv *env) {
    jobject context = getApplication(env);
    // 这里从android/app/Activity取jmethodID而没有从android/content/ContextWrapper或者android/app/Application里取
    // 是用来对抗AndroidNativeEmu框架
    jclass context_wrapper_clz = env->FindClass("android/app/Activity");
    jmethodID getApplicationInfo = env->GetMethodID(context_wrapper_clz, "getApplicationInfo", "()Landroid/content/pm/ApplicationInfo;");
    if (getApplicationInfo == nullptr) {
        return false;
    }
    jobject application_info = env->CallObjectMethod(context, getApplicationInfo);
    if (application_info == nullptr) {
        return false;
    }
    jclass application_info_clz = env->GetObjectClass(application_info);
    jfieldID application_name_id = env->GetFieldID(application_info_clz, "className", "Ljava/lang/String;");

    // 检测Application名是否一致
    auto application_name = (jstring) env->GetObjectField(application_info, application_name_id);
    const char *name = env->GetStringUTFChars(application_name, nullptr);
#if defined( CORRECT_APPLICATION_NAME )
    if (strcmp(name, CORRECT_APPLICATION_NAME) == 0) {
        return true;
    }
#endif
#if defined( CORRECT_APPLICATION_NAME_REINFORCE )
    if (strcmp(name, CORRECT_APPLICATION_NAME_REINFORCE) == 0) {
        return true;
    }
#endif
    return false;
}

/// 检测Application的allowBackup属性
/// 正常情况下应该为false，如果检测到为true，说明应用被Hook了，破解者正在尝试导出应用私有信息
static bool checkApplicationAllowBackup(JNIEnv *env) {
    jobject context = getApplication(env);
    // 这里从android/app/Activity取jmethodID而没有从android/content/ContextWrapper或者android/app/Application里取
    // 是用来对抗AndroidNativeEmu框架
    jclass context_wrapper_clz = env->FindClass("android/app/Activity");
    jmethodID getApplicationInfo = env->GetMethodID(context_wrapper_clz, "getApplicationInfo", "()Landroid/content/pm/ApplicationInfo;");
    if (getApplicationInfo == nullptr) {
        return false;
    }
    jobject application_info = env->CallObjectMethod(context, getApplicationInfo);
    if (application_info == nullptr) {
        return false;
    }
    jclass application_info_clz = env->GetObjectClass(application_info);
    jfieldID application_flags_id = env->GetFieldID(application_info_clz, "flags", "I");

    int application_flags = env->GetIntField(application_info, application_flags_id);
    // FLAG_ALLOW_BACKUP = 1<<15 = 32768
    if ((application_flags & 32768) != 0) {
        return false;
    }
    return true;
}

/// 检测应用版本号
/// 破解者为了防止应用更新导致破解失效，通常会修改此versionCode，因此进行检测
static bool checkVersionCode(JNIEnv *env) {
    jobject context = getApplication(env);
    // 这里从android/app/Activity取jmethodID而没有从android/content/ContextWrapper或者android/app/Application里取
    // 是用来对抗AndroidNativeEmu框架
    jclass context_wrapper_clz = env->FindClass("android/app/Activity");
    jmethodID getPackageManager = env->GetMethodID(context_wrapper_clz, "getPackageManager", "()Landroid/content/pm/PackageManager;");
    if (getPackageManager == nullptr) {
        return false;
    }
    jobject package_manager = env->CallObjectMethod(context, getPackageManager);
    if (package_manager == nullptr) {
        return false;
    }
    jmethodID getPackageName = env->GetMethodID(context_wrapper_clz, "getPackageName", "()Ljava/lang/String;");
    if (getPackageName == nullptr) {
        return false;
    }
    auto application_package = (jstring) env->CallObjectMethod(context, getPackageName);
    jclass package_manager_clz = env->GetObjectClass(package_manager);
    jmethodID getPackageInfo = env->GetMethodID(package_manager_clz, "getPackageInfo", "(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;");
    jobject package_info = env->CallObjectMethod(package_manager, getPackageInfo, application_package, 0x40);
    jclass package_info_clz = env->GetObjectClass(package_info);
    jfieldID version_code_id = env->GetFieldID(package_info_clz, "versionCode", "I");

    int version_code = env->GetIntField(package_info, version_code_id);
#if defined( CORRECT_VERSION_CODE )
    LOGI("checkVersionCode %d %d", version_code, CORRECT_VERSION_CODE);
    if (CORRECT_VERSION_CODE != version_code) {
        return false;
    }
#endif
    return true;
}

/// 检测APK的包名
/// 如果没有指定私有目录的访问权限，说明不是正确的包名
static bool checkPackageName(JNIEnv *env) {
    // 通过检查私有目录的访问权限，判断CORRECT_PACKAGE_NAME是否是当前正在运行的包
    string dir("/data/data/");
#if defined( CORRECT_PACKAGE_NAME )
    dir.append(CORRECT_PACKAGE_NAME);
#endif
    dir.append("/");
    if (opendir(dir.c_str()) == nullptr) {
        return false;
    }
    return true;
}

/// 检测APK的签名
/// 非常基础的检测手段，也容易被一键破解，因此需要配合其他手段防御
static bool checkSignature(JNIEnv *env) {
    jobject context = getApplication(env);
    // 这里从android/app/Activity取jmethodID而没有从android/content/ContextWrapper或者android/app/Application里取
    // 是用来对抗AndroidNativeEmu框架
    jclass context_wrapper_clz = env->FindClass("android/app/Activity");
    jmethodID getPackageManager = env->GetMethodID(context_wrapper_clz, "getPackageManager", "()Landroid/content/pm/PackageManager;");
    if (getPackageManager == nullptr) {
        return false;
    }
    jobject package_manager = env->CallObjectMethod(context, getPackageManager);
    if (package_manager == nullptr) {
        return false;
    }
    jmethodID getPackageName = env->GetMethodID(context_wrapper_clz, "getPackageName", "()Ljava/lang/String;");
    if (getPackageName == nullptr) {
        return false;
    }
    auto application_package = (jstring) env->CallObjectMethod(context, getPackageName);
    jclass package_manager_clz = env->GetObjectClass(package_manager);
    jmethodID getPackageInfo = env->GetMethodID(package_manager_clz, "getPackageInfo", "(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;");
    jobject package_info = env->CallObjectMethod(package_manager, getPackageInfo, application_package, 0x40);
    jclass package_info_clz = env->GetObjectClass(package_info);
    jfieldID signatures_id = env->GetFieldID(package_info_clz, "signatures", "[Landroid/content/pm/Signature;");
    auto signs = (jobjectArray) env->GetObjectField(package_info, signatures_id);
    jobject sign = env->GetObjectArrayElement(signs, 0);
    jclass signature_clz = env->GetObjectClass(sign);
    jmethodID toCharsString = env->GetMethodID(signature_clz, "toCharsString", "()Ljava/lang/String;");
    if (toCharsString == nullptr) {
        return false;
    }
    auto sign_jstr = (jstring) env->CallObjectMethod(sign, toCharsString);
    const char *sign_chars = env->GetStringUTFChars(sign_jstr, nullptr);
    string sign_str(sign_chars);
    env->ReleaseStringUTFChars(sign_jstr, sign_chars);

    // 检测签名md5值是否一致
    string apkSignature = md5(sign_str);
//    LOGE("checkSignature %s", apkSignature.c_str());
#if defined( CORRECT_APK_SIGN )
    if (apkSignature != CORRECT_APK_SIGN) {
        return false;
    }
#endif
    return true;
}

/// 检测Native与Java层获取到的APK的文件路径或者大小
/// 因为pm命令获取到的APK文件路径通常不容易被修改，这里与通过JavaApi获取到的APK文件路径做比较，如果文件路径或者文件大小不一致时
/// 大概率是应用被IO重定向了，或者使用了VirtualXposed等分身软件
static bool checkAPKFile(JNIEnv *env) {
    jobject context = getApplication(env);
    // 这里从android/app/Activity取jmethodID而没有从android/content/ContextWrapper或者android/app/Application里取
    // 是用来对抗AndroidNativeEmu框架
    jclass context_wrapper_clz = env->FindClass("android/app/Activity");
    jmethodID getPackageCodePath = env->GetMethodID(context_wrapper_clz, "getPackageCodePath", "()Ljava/lang/String;");
    if (getPackageCodePath == nullptr) {
        return false;
    }

    auto apk_path_jstr = (jstring) env->CallObjectMethod(context, getPackageCodePath);
    const char *apk_path_chars = env->GetStringUTFChars(apk_path_jstr, nullptr);
    const char *native_apk_path_chars = getRealAPKPath();
    // 当Native与Java层获取到的APK文件路径或者文件大小不一致时，大概率是被IO重定向了，或者使用了VirtualXposed等分身软件
    if (apk_path_chars != nullptr
        && native_apk_path_chars != nullptr
        && (strcmp(apk_path_chars, native_apk_path_chars) != 0 || getFileSize(apk_path_chars) != getFileSize(native_apk_path_chars))) {
        return false;
    }
    return true;
}

/// 通过调用RegisterNatives方法来注册我们的函数
static int registerNativeMethods(JNIEnv *env) {
    // 找到声明native方法的类
    jclass clazz = env->FindClass(className);
    if (clazz == nullptr) {
        return JNI_FALSE;
    }
    // 注册函数 参数：java类 所要注册的函数数组 注册函数的个数
    if (env->RegisterNatives(clazz, jniMethods, sizeof(jniMethods) / sizeof(jniMethods[0])) < 0) {
        return JNI_FALSE;
    }
    return JNI_TRUE;
}

/// JNI初始化回调
jint JNI_OnLoad(JavaVM *vm, void *reserved) {
    JNIEnv *env = nullptr;
    if (vm->GetEnv((void **) &env, JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR;
    }

    // 检测是否被动态调试 【可选】建议Release阶段开启
    if (checkDebug(env)) {
        LOGI("checkDebug failed.");
        return JNI_ERR;
    }

    // 检测APK的签名 必要，基本的防破解手段
    if (!checkSignature(env)) {
        LOGI("checkSignature failed.");
        return JNI_ERR;
    }

    // 检测APK的包名 【可选】如允许用户双开，可关闭此检测
    if (!checkPackageName(env)) {
        LOGI("checkPackageName failed.");
        return JNI_ERR;
    }

    // 检测是否被Xposed等框架注入 必要，基本的防破解手段
    if (checkXposedOrCydia(env)) {
        LOGI("checkXposedOrCydia failed.");
        return JNI_ERR;
    }

    // 检测PMS是否被Hook 【可选】基本的防破解手段，如允许用户双开，可关闭此检测
    if (checkHookPMS(env)) {
        LOGI("checkHookPMS failed.");
        return JNI_ERR;
    }

    // 检测Application的className属性 必要，基本的防破解手段
    if (!checkApplicationName(env)) {
        LOGI("checkApplicationName failed.");
        return JNI_ERR;
    }

    // 检测Application的allowBackup属性 【可选】用处不大，Root后的手机不修改该值依然可导出用户私有信息
    if (!checkApplicationAllowBackup(env)) {
        LOGI("checkApplicationAllowBackup failed.");
        return JNI_ERR;
    }

    // 检测应用版本号 必要，基本的防破解手段
    if (!checkVersionCode(env)) {
        LOGI("checkVersionCode failed.");
        return JNI_ERR;
    }

    // 检测Native与Java层获取到的APK的文件路径或者大小 【可选】如允许用户双开，可关闭此检测
    if (!checkAPKFile(env)) {
        LOGI("checkAPKFile failed.");
        return JNI_ERR;
    }

    // 注册函数
    if (!registerNativeMethods(env)) {
        LOGI("registerNativeMethods failed.");
        return JNI_ERR;
    }

    return JNI_VERSION_1_6;
}

static jstring charToJstring(JNIEnv *env, char *src) {
    jsize len = strlen(src);
    jclass clsstring = env->FindClass("java/lang/String");
    jstring strencode = env->NewStringUTF("UTF-8");
    jmethodID mid = env->GetMethodID(clsstring, "<init>", "([BLjava/lang/String;)V");
    jbyteArray barr = env->NewByteArray(len);
    env->SetByteArrayRegion(barr, 0, len, (jbyte *) src);
    return (jstring) env->NewObject(clsstring, mid, barr, strencode);
}

jstring encrypt(JNIEnv *env, jobject thiz, jstring jstr) {
    if (nullptr == jstr) {
        return env->NewStringUTF("");
    }

    const char *str = env->GetStringUTFChars(jstr, nullptr);
    char *encrypt_result = aes_encrypt(str, SECRET_KEY);

    env->ReleaseStringUTFChars(jstr, str);

    jstring result;
    if (nullptr != encrypt_result) {
        result = env->NewStringUTF(encrypt_result);
        free(encrypt_result);
    } else {
        result = env->NewStringUTF("");
    }
    return result;
}

jstring decrypt(JNIEnv *env, jobject thiz, jstring jstr) {
    if (nullptr == jstr) {
        return env->NewStringUTF("");
    }

    const char *str = env->GetStringUTFChars(jstr, nullptr);
    char *decrypt_result = aes_decrypt(str, SECRET_KEY);

    env->ReleaseStringUTFChars(jstr, str);

    jstring result;
    if (nullptr != decrypt_result) {
        // 不用系统自带的方法NewStringUTF是因为如果decrypt_result是乱码,会抛出异常
        result = charToJstring(env, decrypt_result);
        free(decrypt_result);
    } else {
        result = env->NewStringUTF("");
    }
    return result;
}

/// 返回当前APK文件和此加密So包的文件信息用于服务器校验
jstring integrity(JNIEnv *env, jobject thiz) {
    const char *path = getRealAPKPath();
    int size = getFileSize(path);
    const char *dir = getFileDir(path);
    string tmp("{");
    tmp.append("\"ApkPath\":");
    tmp.append("\"");
    tmp.append(path);
    tmp.append("\"");
    tmp.append(",");
    tmp.append("\"ApkSize\":");
    tmp.append(std::to_string(size));
    tmp.append(",");
//    // 由于大文件MD5计算比较费时，所以不提供此数据
//    tmp.append("\"ApkMD5\":");
//    tmp.append("\"");
//    tmp.append(md5file(path));
//    tmp.append("\"");
//    tmp.append(",");
    char *abi = (char *) malloc(128);
    __system_property_get("ro.product.cpu.abilist", abi);
    string so(dir);
    if (strncmp(abi, "arm64-v8a", 9) == 0) {
        // arm64
        so.append("/lib/arm64/libezcore.so");
    } else {
        // arm
        so.append("/lib/arm/libezcore.so");
    }
    tmp.append("\"SoPath\":");
    tmp.append("\"");
    tmp.append(so);
    tmp.append("\"");
    tmp.append(",");
    tmp.append("\"SoSize\":");
    tmp.append(std::to_string(getFileSize(&so[0])));
    tmp.append(",");
    tmp.append("\"SoMD5\":");
    tmp.append("\"");
    tmp.append(md5file(so.c_str()));
    tmp.append("\"");
    tmp.append("}");
    return env->NewStringUTF(tmp.c_str());
}
