find_package(OpenSSL REQUIRED)

add_library(rapidjson INTERFACE)
target_include_directories(rapidjson INTERFACE rapidjson/include/)

add_library(argmap INTERFACE)
target_include_directories(argmap INTERFACE argmap/)

add_library(net INTERFACE)
target_include_directories(net INTERFACE net/)

add_library(evp openssl/evp.h openssl/evp.cpp)
target_include_directories(evp PUBLIC openssl/)
target_link_libraries(evp PRIVATE OpenSSL::SSL OpenSSL::Crypto)

add_library(tableprinter INTERFACE)
target_include_directories(tableprinter INTERFACE tableprinter/)