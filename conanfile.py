# pylint: skip-file

import os
from conan import ConanFile
from conan.tools.cmake import cmake_layout, CMake, CMakeToolchain

class BslngRecipe(ConanFile):
    settings = "os", "compiler", "build_type", "arch"
    generators = "CMakeDeps"

    def requirements(self):
        self.requires("jansson/[>=2.10 <3]")
        self.requires("libuv/[>=1.10.2 <2]")

    def build_requirements(self):
        self.tool_requires("cmake/[~3.23]")

    def generate(self):
        tc = CMakeToolchain(self)
        tc.variables["BUILD_TYPE"] = self.settings.build_type
        tc.generate()

    def build(self):
        cmake = CMake(self)
        cmake.configure()
        cmake.build()

    def layout(self):
        cmake_layout(self)
