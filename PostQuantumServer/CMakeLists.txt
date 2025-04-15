# CMakeLists.txt: CMake project for PostQuantumServer
cmake_minimum_required(VERSION 3.8)


if (POLICY CMP0141)
  cmake_policy(SET CMP0141 NEW)
  set(CMAKE_MSVC_DEBUG_INFORMATION_FORMAT "$<IF:$<AND:$<C_COMPILER_ID:MSVC>,$<CXX_COMPILER_ID:MSVC>>,$<$<CONFIG:Debug,RelWithDebInfo>:EditAndContinue>,$<$<CONFIG:Debug,RelWithDebInfo>:ProgramDatabase>>")
endif()

project("PostQuantumServer")

# 1) Add the subdirectory where your PQClean-master/CMakeLists.txt lives.
#    This will build the library from sources.
add_subdirectory(PQClean-master)

# 2) Create the executable from your main source files
add_executable(PostQuantumServer
    PostQuantumServer.cpp
    PostQuantumServer.h
 "Helpers.cpp")

# 3) Optionally set the C++ standard
if (CMAKE_VERSION VERSION_GREATER 3.12)
    set_property(TARGET PostQuantumServer PROPERTY CXX_STANDARD 20)
endif()

# 4) Link the library (ml_dsa_65_clean) we define in the PQClean-master subdirectory
target_link_libraries(PostQuantumServer PRIVATE ml_dsa_65_clean)

# If you need any special include directory beyond what's set in the subdirectory,
# add it here. For example:
# target_include_directories(PostQuantumServer PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/some_include")