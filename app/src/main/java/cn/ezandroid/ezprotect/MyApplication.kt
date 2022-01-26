package cn.ezandroid.ezprotect

import android.app.Application
import android.content.Context

class MyApplication : Application() {

    override fun attachBaseContext(base: Context?) {
        super.attachBaseContext(base)
    }

    override fun onCreate() {
        super.onCreate()
    }
}