# For more information about using CMake with Android Studio, read the
# documentation: https://d.android.com/studio/projects/add-native-code.html

# Sets the minimum version of CMake required to build the native library.

cmake_minimum_required(VERSION 3.18.1)

#-mllvm -fla 控制流扁平化
#-mllvm -sub 指令替换
#-mllvm -bcf 虚假控制流程
#-mllvm -sobf 字符串加密
set(CMAKE_CXX_FLAGS "-mllvm -fla -mllvm -sub -mllvm -sobf ${CMAKE_CXX_FLAGS}")

# Creates and names a library, sets it as either STATIC
# or SHARED, and provides the relative paths to its source code.
# You can define multiple libraries, and CMake builds them for you.
# Gradle automatically packages shared libraries with your APK.

file(GLOB native_src
        "src/main/cpp/util/*.cpp"
        "src/main/cpp/protect/*.cpp"
        )
add_library( # Sets the name of the library.
        ezcore

        # Sets the library as a shared library.
        SHARED

        # Provides a relative path to your source file(s).
        ${native_src})

# Searches for a specified prebuilt library and stores the path as a
# variable. Because CMake includes system libraries in the search path by
# default, you only need to specify the name of the public NDK library
# you want to add. CMake verifies that the library exists before
# completing its build.

find_library( # Sets the name of the path variable.
        log-lib

        # Specifies the name of the NDK library that
        # you want CMake to locate.
        log)

# Specifies libraries CMake should link to your target library. You
# can link multiple libraries, such as libraries you define in this
# build script, prebuilt third-party libraries, or system libraries.

target_link_libraries( # Specifies the target library.
        ezcore

        # Links the target library to the log library
        # included in the NDK.
        ${log-lib})

add_definitions("-fvisibility=hidden")

# APK签名MD5值
add_definitions(-DCORRECT_APK_SIGN="${CORRECT_APK_SIGN}")
# APK包名
add_definitions(-DCORRECT_PACKAGE_NAME="${CORRECT_PACKAGE_NAME}")
# Application名
add_definitions(-DCORRECT_APPLICATION_NAME="${CORRECT_APPLICATION_NAME}")
# 加固后的Application名 【可选】比如360免费加固后的Application名为com.stub.StubApp
add_definitions(-DCORRECT_APPLICATION_NAME_REINFORCE="")
# 版本号，破解者为了防止应用更新导致破解失效，通常会修改此versionCode，因此进行检测
add_definitions(-DCORRECT_VERSION_CODE=${CORRECT_VERSION_CODE})