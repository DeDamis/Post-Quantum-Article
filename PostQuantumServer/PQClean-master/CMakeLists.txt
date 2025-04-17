cmake_minimum_required(VERSION 3.8)
project(PQClean C)

# 1) Spoleèné zdroje
file(GLOB PQCLEAN_COMMON_SRCS
    "${CMAKE_CURRENT_SOURCE_DIR}/common/*.c"
)

# 2) ML-DSA (sign) zdroje
file(GLOB MLDSA_SRCS
    "${CMAKE_CURRENT_SOURCE_DIR}/crypto_sign/ml-dsa-44/clean/*.c"
)

# 3) ML-KEM (kem) zdroje
file(GLOB MLKEM_SRCS
    "${CMAKE_CURRENT_SOURCE_DIR}/crypto_kem/ml-kem-512/clean/*.c"
)

# 4) Knihovna pro podepisování
add_library(ml_dsa_44_clean STATIC
    ${PQCLEAN_COMMON_SRCS}
    ${MLDSA_SRCS}
)
target_include_directories(ml_dsa_44_clean PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}/common"
    "${CMAKE_CURRENT_SOURCE_DIR}/crypto_sign/ml-dsa-44/clean"
)
set_property(TARGET ml_dsa_44_clean PROPERTY C_STANDARD 99)

# 5) Knihovna pro KEM
add_library(ml_kem_512_clean STATIC
    ${PQCLEAN_COMMON_SRCS}
    ${MLKEM_SRCS}
)
target_include_directories(ml_kem_512_clean PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}/common"
    "${CMAKE_CURRENT_SOURCE_DIR}/crypto_kem/ml-kem-512/clean"
)
set_property(TARGET ml_kem_512_clean PROPERTY C_STANDARD 99)

