cmake_minimum_required(VERSION 3.18.1)
project("native_hook")

add_library(native_hook SHARED
    native_hook.c
    plt_hook.c
)

target_link_libraries(native_hook
    log
    dl
)
