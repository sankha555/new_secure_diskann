cmake_minimum_required(VERSION 3.22.1 FATAL_ERROR)
project(secure_diskann)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,--copy-dt-needed-entries")

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -mavx2 -mfma -msse2 -ftree-vectorize -Ofast -fopenmp -fopenmp-simd -funroll-loops -Wfatal-errors -DUSE_AVX2")

include_directories(${CMAKE_SOURCE_DIR}/src)

find_package(Boost REQUIRED COMPONENTS program_options)

add_subdirectory(src)

add_executable(client ./src/client.cpp ./src/oram/config_parser.cpp ./src/oram/OramAPI.cpp ./src/diskann/oram_index.cpp)
target_include_directories(client PRIVATE ${CMAKE_SOURCE_DIR}/src/diskann ${CMAKE_SOURCE_DIR}/src/diskann/include)
target_link_libraries(client PRIVATE oram_library argmap rapidjson Boost::program_options diskann aio)

add_executable(server ./src/server.cpp ./src/oram/config_parser.cpp ./src/oram/OramAPI.cpp)
target_link_libraries(server PRIVATE oram_library argmap rapidjson)

add_executable(oram_initializer ./src/oram/oram_initialization.cpp ./src/oram/OramAPI.cpp ./src/oram/config_parser.cpp ./src/oram/node.cpp)
target_include_directories(client PRIVATE ${CMAKE_SOURCE_DIR}/src/diskann ${CMAKE_SOURCE_DIR}/src/diskann/include)
target_link_libraries(oram_initializer PRIVATE oram_library argmap rapidjson Boost::program_options diskann aio)
