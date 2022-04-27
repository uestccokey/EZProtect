# EZProtect

一个Native层的Android应用防护库

去年在开发一个个人项目的过程中，发现自己的应用被人破解修改，并且被二次打包放到了网上，因此对应用安全防护进行了一点研究。

虽然市场上大部分App已经进行了代码混淆、签名校验和Dex加固，但是现在的破解工具太方便了。诸如脱壳、去签名、重打包等功能，手机安装MT管理器或者NP管理器后都可以一条龙完成，因此需要继续增加破解难度。

国内开发者用的最多的防护库可能是 https://github.com/lamster2018/EasyProtector ，该库集成了不少检测方法，但是他的重大缺点就是校验方法放在Java层，使用Xposed等框架可以轻易过掉检测，因此实现了一个Native层的Android应用防篡改库。

### 防护能力

1.防动态调试

2.防逆向分析

3.防恶意注入

4.防二次打包

5.防数据窃取

### 检测功能

#### 1.检测是否被动态调试

有经验的破解者通常会通过IDA等工具来动态调试So，以过掉So库中的检测功能，因此首先需要对动态调试进行拦截，通常采用

1.通过ptrace自添加防止被调试器挂载来反调试

2.通过检查TracePid!=0来进行判断

3.通过系统提供的Debug.isDebuggerConnected()方法来进行判断

#### 2.检测APK的签名

非常基础的检测手段，因为容易被一键破解，因此需要配合其他手段防御

#### 3.检测APK的包名

判断opendir("/data/data/CORRECT_PACKAGE_NAME")是否等于nullptr，如果没有指定私有目录的访问权限，说明不是正确的包名

#### 4.检测是否被Xposed等框架注入

检测"/proc/self/maps"目录下的文件，如果出现包含xposed、substrate、frida等名称的文件，说明有框架正在注入

#### 5.检测PMS是否被Hook

通过检测PMS是否继承Proxy类可以知道是否已被Hook

#### 6.检测Application的className属性

大部分工具都会通过修改入口Application类，并在修改后的Application类中添加各种破解代码来实现去签名校验，它们常常费了很大的劲比如Hook了PMS，同时为了防止你读取原包做文件完整性校验可能还进行了IO重定向，但偏偏忽视了对Application类名的隐藏，经测试该检测可以防御大部分工具的一键破解

#### 7.检测Application的allowBackup属性

正常情况下应该为false，如果检测到为true，说明应用被Hook了，破解者正在尝试导出应用私有信息

#### 8.检测应用版本号

破解者为了防止应用更新导致破解失效，通常会修改此versionCode，因此需要进行检测

#### 9.检测Native与Java层获取到的APK的文件路径或者大小

因为pm命令获取到的APK文件路径通常不容易被修改，这里与通过JavaApi获取到的APK文件路径做比较，如果文件路径或者文件大小不一致时，大概率是应用被IO重定向了，或者使用了VirtualXposed等分身软件

#### 10.Apk和So文件完整性校验

可以获取到当前APK文件和此加密So包的文件信息用于服务器校验

注意，编译时需要使用Ollvm混淆，配置可以参考文章

https://blog.csdn.net/u013314647/article/details/117740784?utm_medium=distribute.pc_relevant.none-task-blog-2~default~baidujs_title~default-0.no_search_link&spm=1001.2101.3001.4242
