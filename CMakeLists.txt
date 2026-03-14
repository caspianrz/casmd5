cmake_minimum_required(VERSION 3.12)

project(casmd5
	VERSION 1.0.0
	DESCRIPTION "Caspian MD5 hashing library."
	LANGUAGES C
)

add_library(casmd5 cmd5.c)
add_executable(cmd5digest main.c)
target_link_libraries(cmd5digest PRIVATE casmd5)
