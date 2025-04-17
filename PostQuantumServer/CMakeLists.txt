# CMakeLists.txt: CMake project for PostQuantumServer
cmake_minimum_required(VERSION 3.8)


if (POLICY CMP0141)
  cmake_policy(SET CMP0141 NEW)
  set(CMAKE_MSVC_DEBUG_INFORMATION_FORMAT "$<IF:$<AND:$<C_COMPILER_ID:MSVC>,$<CXX_COMPILER_ID:MSVC>>,$<$<CONFIG:Debug,RelWithDebInfo>:EditAndContinue>,$<$<CONFIG:Debug,RelWithDebInfo>:ProgramDatabase>>")
endif()

project("PostQuantumServer" LANGUAGES C CXX)

# 1) Sestavíme podprojekt PQClean-master (vytvoří ml_dsa_44_clean a ml_kem_512_clean)
add_subdirectory(PQClean-master)

# 2) Definice hlavního programu
add_executable(PostQuantumServer
    PostQuantumServer.cpp
    Helpers.cpp
)

# 3) C++20
if (CMAKE_VERSION VERSION_GREATER 3.12)
  set_property(TARGET PostQuantumServer PROPERTY CXX_STANDARD 20)
endif()

# 4) Link ml-dsa-44 i ml-kem-512 knihovny
target_link_libraries(PostQuantumServer PRIVATE
    ml_dsa_44_clean
    ml_kem_512_clean
)

# 5) (volitelné) Pokud potřebuješ ještě další include cesty:
# target_include_directories(PostQuantumServer PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")