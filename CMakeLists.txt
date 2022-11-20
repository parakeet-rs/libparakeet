cmake_minimum_required(VERSION 3.21)
project(parakeet_crypro VERSION 0.2.1 LANGUAGES CXX)

option(PARAKEET_CRYPTO_BUILD_TESTING "Build library tests" ON)

find_program(CCACHE_TOOL_PATH ccache) # Optional

include(cmake/CPM-Loader.cmake)

CPMAddPackage(
  NAME cryptopp-cmake
  GITHUB_REPOSITORY abdes/cryptopp-cmake
  GIT_TAG CRYPTOPP_8_7_0
  OPTIONS
    "CRYPTOPP_BUILD_TESTING OFF"
)

if (!MSVC)
	link_libraries(m)

  # Enable Ccache.
  if (CCACHE_TOOL_PATH)
    CPMAddPackage(
      NAME Ccache.cmake
      GITHUB_REPOSITORY TheLartians/Ccache.cmake
      VERSION 1.2
    )
  endif()
endif()

set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS YES CACHE BOOL "Export all symbols")

configure_file (
    "${PROJECT_SOURCE_DIR}/src/version.cpp.in"
    "${PROJECT_BINARY_DIR}/src/version.cpp"
)

file(GLOB_RECURSE SOURCES
  "src/*.h"
  "src/*.cpp"
  "${PROJECT_BINARY_DIR}/src/*.h"
  "${PROJECT_BINARY_DIR}/src/*.cpp"
)

# Add source to this project's executable.
add_library (parakeet_crypro STATIC ${SOURCES})
add_library(ParakeetCrypto::core ALIAS parakeet_crypro)

target_include_directories(parakeet_crypro
  PUBLIC 
    $<INSTALL_INTERFACE:include>    
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  PRIVATE
    src
    "${PROJECT_BINARY_DIR}/src"
)
target_link_libraries(parakeet_crypro PRIVATE cryptopp::cryptopp)
target_compile_features(parakeet_crypro PRIVATE cxx_std_20)

include(GNUInstallDirs)
set(INSTALL_CONFIGDIR ${CMAKE_INSTALL_LIBDIR}/cmake/parakeet_crypro)

install(TARGETS parakeet_crypro
    EXPORT parakeet_crypro-targets
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)
set_target_properties(parakeet_crypro PROPERTIES EXPORT_NAME ParakeetCrypto)

install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(EXPORT parakeet_crypro-targets
  FILE
    ParakeetCryptoTargets.cmake
  NAMESPACE
    ParakeetCrypto::
  DESTINATION
    ${CMAKE_INSTALL_LIBDIR}/cmake/parakeet_crypro
)

# Tests!
if(PARAKEET_CRYPTO_BUILD_TESTING)
  enable_testing()
  CPMAddPackage(
    NAME googletest
    GITHUB_REPOSITORY google/googletest
    GIT_TAG release-1.12.1
    VERSION 1.12.1
    OPTIONS
        "INSTALL_GTEST OFF"
        "gtest_force_shared_crt ON"
  )

  file(GLOB_RECURSE TESTS_SOURCE src/*.test.cc src/*.test.hh)
  add_executable(parakeet_crypto_test ${TESTS_SOURCE})
  target_include_directories(parakeet_crypto_test PRIVATE src)
  target_compile_features(parakeet_crypto_test PRIVATE cxx_std_20)
  target_link_libraries(parakeet_crypto_test 
    cryptopp::cryptopp
    GTest::gmock
    GTest::gtest
    GTest::gmock_main
    GTest::gtest_main
    ${PROJECT_NAME}
  )

  include(GoogleTest)
  gtest_discover_tests(parakeet_crypto_test)
endif()
