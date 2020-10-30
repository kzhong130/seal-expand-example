add_executable(expand expand-3.5.6.cpp)
find_package(SEAL 3.5 REQUIRED)
target_link_libraries(expand SEAL::seal)