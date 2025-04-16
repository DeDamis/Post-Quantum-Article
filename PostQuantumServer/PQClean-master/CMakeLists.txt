cmake_minimum_required(VERSION 3.8)
project("PQClean" C)

# Collect all C sources from "common" and "crypto_sign/ml-dsa-44/clean"
file(GLOB PQCLEAN_COMMON_SRCS
    "${CMAKE_CURRENT_SOURCE_DIR}/common/*.c"
)
file(GLOB MLDSA_SRCS
    "${CMAKE_CURRENT_SOURCE_DIR}/crypto_sign/ml-dsa-44/clean/*.c"
)

# Create a static library from these sources
add_library(ml_dsa_44_clean STATIC
    ${PQCLEAN_COMMON_SRCS}
    ${MLDSA_SRCS}
)

# Add include directories so that #include "api.h", etc. works
target_include_directories(ml_dsa_44_clean PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}/common"
    "${CMAKE_CURRENT_SOURCE_DIR}/crypto_sign/ml-dsa-44/clean"
)

# If you have compiler flags or definitions that the library requires (e.g. -Wall),
# you can set them here:
# target_compile_options(ml_dsa_44_clean PRIVATE -Wall -Wextra)
