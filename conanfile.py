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
    options = {"hello": [True, False]}
    default_options = {"hello": False}

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
        tc.user_presets_path = "out/unused.json" # don't bother
        tc.generate()

    def build(self):
        cmake = CMake(self)
        cmake.configure()
        cmake.build()

    def package(self):
        cmake = CMake(self)
        cmake.install()

    def requirements(self):
        self.requires("cryptopp/8.7.0")
        self.requires("openssl/3.1.1")
        self.requires("zlib/1.2.13")

    def package_info(self):
        self.cpp_info.libs = ["libparakeet"]
