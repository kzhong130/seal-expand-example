add_executable(expand expand-3.2.0.cpp)
find_package(SEAL 3.2.0 REQUIRED)
target_link_libraries(expand SEAL::seal)