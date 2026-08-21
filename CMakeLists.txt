cmake_minimum_required(VERSION 3.16)
project(SantetSentinel-AuthSDK LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ── SDK Library ──────────────────────────────────────────────────────────────
add_library(authss STATIC
    cpp/include/authSS/authSS.cpp
    cpp/include/authSS/Security.cpp
)

target_include_directories(authss PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/cpp/include
)

if(WIN32)
    target_link_libraries(authss PUBLIC
        winhttp bcrypt crypt32 advapi32 psapi
    )
    target_compile_definitions(authss PUBLIC
        WIN32_LEAN_AND_MEAN NOMINMAX
    )
endif()

# ── Examples ─────────────────────────────────────────────────────────────────
option(BUILD_EXAMPLES "Build example programs" ON)

if(BUILD_EXAMPLES)
    foreach(example basic login security)
        if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/cpp/examples/${example}/main.cpp")
            add_executable(authss-${example} cpp/examples/${example}/main.cpp)
            target_link_libraries(authss-${example} PRIVATE authss)
        endif()
    endforeach()
endif()
