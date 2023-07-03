# LibParakeet

使用 C++ 实现的小鹦鹉流媒体解密操作库。

## 构建

使用 `conan` 安装预编译的依赖，然后使用 CMake 进行构建。

```sh
conan profile detect # if not used before
conan install . --output-folder=out/deps --build=missing --settings=build_type=Release
conan install . --output-folder=out/deps --build=missing --settings=build_type=Debug
```

## 用例

参考 `examples` 目录下的子项目。

💡 内置的默认密钥不能用于解密生产版本的文件。

### QMC2

命令行程序示例；传入 `<输入路径> <输出路径>` 这两个参数运行。

代码清单：

* `examples/qmc2/src/qmc2-example.cpp`
* `examples/qmc2/src/qmc2-key.local.h` (可选)

Linux 下编译/运行：

```bash
# Configure & Build
cmake --preset ninja
cmake --build --preset "ninja-release" --target qmc2

# Run
./out/build/ninja/examples/qmc2/Release/qmc2 "test.mflac" "test.flac"
```

### qrc-decode

命令行程序示例；传入 `<输入路径> <输出路径>` 这两个参数运行。

代码清单：

* `examples/qrc/src/qrc-example.cpp`
* `examples/qrc/src/qrc-key.local.h` (可选)

Linux 下编译/运行：

```bash
# Configure & Build
cmake --preset ninja
cmake --build --preset "ninja-release" --target qrc-decode

# Run
./out/build/ninja/examples/qrc/Release/qrc-decode "test.qrc" "test.qrc.xml"
```

## 发布新版本

1. 更新 `CHANGELOG.md`
2. 更新 `CMakeLists.txt` 声明的版本号
3. 合并到主分支，然后打上 `git tag`

## License

Licensed under the [MIT License](LICENSE.txt).
