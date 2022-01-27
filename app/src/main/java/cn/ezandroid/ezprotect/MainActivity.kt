package cn.ezandroid.ezprotect

import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import android.widget.TextView
import cn.ezandroid.lib.ezprotect.Native

class MainActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        findViewById<TextView>(R.id.info).text = Native.decrypt(Native.encrypt("ezproject")) + " : " + Native.integrity()
    }
}