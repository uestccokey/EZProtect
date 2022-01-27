package cn.ezandroid.lib.ezprotect

/**
 * Jni接口，通过动态注册，因此该类不能混淆，为避免破解者反编译后通过函数名了解函数实际功能，这里使用无意义方法名，应用时通过Native类进行调用
 */
class NativeApi {

    init {
        System.loadLibrary("ezcore")
    }

    /**
     * AES加密
     *
     * @param text
     */
    external fun a(text: String): String

    /**
     * AES解密
     *
     * @param text
     */
    external fun b(text: String): String

    /**
     * 当前APK文件和此加密So包的文件信息用于服务器校验或攻击预警
     */
    external fun c(): String
}

/**
 * 该类可混淆，因此破解者反编译后无法通过函数名了解函数实际功能
 */
object Native {
    private val api: NativeApi by lazy { NativeApi() }

    fun encrypt(text: String): String {
        return if (text.isNotEmpty()) api.a(text) else ""
    }

    fun decrypt(text: String): String {
        return if (text.isNotEmpty()) api.b(text) else ""
    }

    fun integrity(): String {
        return api.c()
    }
}