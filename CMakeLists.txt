cmake_minimum_required(VERSION 3.13)

project(itchsender LANGUAGES C CXX VERSION 1.0.0)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
if (MSVC)
  add_compile_options(/permissive-) # no /MP - use Ninja instead
  add_definitions(-D_CRT_SECURE_NO_WARNINGS -D_CRT_NONSTDC_NO_WARNINGS -D_WIN32_WINNT=0x0601)
endif()

find_package(Threads REQUIRED)
if (MSVC)
  set(Boost_USE_STATIC_LIBS ON)
  # b2 -j8 address-model=64 architecture=x86 variant=debug variant=release link=static runtime-link=static runtime-link=shared
  set(Boost_ADDITIONAL_VERSIONS "1.75.0")
  set(BOOST_INCLUDEDIR /boost)
  set(BOOST_LIBRARYDIR /boost/stage/lib)
endif()
# sudo apt-get install libboost-all-dev
find_package(Boost 1.67 REQUIRED COMPONENTS system program_options iostreams date_time regex)

enable_testing()

add_subdirectory(libitchsender)
add_subdirectory(main)
add_subdirectory(tests)
