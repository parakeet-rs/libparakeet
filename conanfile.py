from conan import ConanFile
from conan.tools.cmake import CMakeToolchain, CMake, cmake_layout, CMakeDeps


class libparakeetRecipe(ConanFile):
    name = "libparakeet"
    version = "0.5"

    # Optional metadata
    license = "MIT"
    author = "Jixun <i@jixun.moe>"
    url = "https://github.com/parakeet-rs/libparakeet"
    description = "Libparakeet (TODO)"
    topics = ("libparakeet", )

    # Binary configuration
    settings = "os", "compiler", "build_type", "arch"
    options = {"gtest": [True, False]}
    default_options = {"gtest": False}

    # Sources are located in the same place as this recipe, copy them to the recipe
    exports_sources = "CMakeLists.txt", "src/*", "include/*"

    def config_options(self):
        pass

    def configure(self):
        pass

    def layout(self):
        cmake_layout(self)

    def generate(self):
        deps = CMakeDeps(self)
        deps.generate()
        tc = CMakeToolchain(self)
        tc.generate()

    def build(self):
        cmake = CMake(self)
        cmake.configure()
        cmake.build()

    def package(self):
        cmake = CMake(self)
        cmake.install()

    def requirements(self):
        self.requires("openssl/3.1.1")
        if self.options.gtest:
            self.requires("gtest/cci.20210126")

    def package_info(self):
        self.cpp_info.libs = ["libparakeet"]
