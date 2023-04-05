cmake_minimum_required(VERSION 3.21)

project(encryptool LANGUAGES CXX C)

# Enable extra find_package modules
set(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake/modules)

# On Windows, it's requried that user specify vcpkg.cmake in CMAKE_TOOLCHAIN_FILE variable

# Find the library
find_package(OpenSSL REQUIRED)

# Set up the executable target
add_executable(${PROJECT_NAME} 
    main.cpp
    src/encryptool.cpp
    )

list(FIND CMAKE_CXX_COMPILE_FEATURES cxx_std_17 __cxx17_support)
if (__cxx17_support)
    message(STATUS "Using std::filesystem from c++17")
    target_compile_features(${PROJECT_NAME} PRIVATE cxx_std_17)
    target_compile_definitions(${PROJECT_NAME} PRIVATE USE_STD_FILESYSTEM)
    if(WIN32)
        find_package(Boost REQUIRED COMPONENTS program_options stacktrace_windbg)
    else()
        find_package(Boost REQUIRED COMPONENTS program_options stacktrace_backtrace)
    endif()
else()
    message(STATUS "try to use boost::filesystem")
    target_compile_features(${PROJECT_NAME} PRIVATE cxx_std_11)
    if (WIN32)
        find_package(Boost REQUIRED COMPONENTS filesystem program_options stacktrace_windbg)
    else()
        find_package(Boost REQUIRED COMPONENTS filesystem program_options stacktrace_backtrace)
    endif()
endif()

# Set include dirs
target_include_directories(${PROJECT_NAME}
    PUBLIC
        $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
    PRIVATE
        ${PROJECT_SOURCE_DIR}/src
)

target_link_options(${PROJECT_NAME}
    PRIVATE
        -rdynamic)

# Link to thirdparty libraries
target_link_libraries(${PROJECT_NAME}
    PRIVATE
        $<$<BOOL:${WIN32}>:Dbghelp>
        $<$<BOOL:${WIN32}>:Boost::stacktrace_windbg>
        $<$<BOOL:${UNIX}>:Boost::stacktrace_backtrace>
        $<$<BOOL:${UNIX}>:dl>
        Boost::program_options
        OpenSSL::SSL
        OpenSSL::Crypto
    )

include(GNUInstallDirs)
# Set up the installation 
install(TARGETS ${PROJECT_NAME} 
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    INCLUDES DESTINATION include/encryptool)

# Set up CPack
if(UNIX)
    # Check if the platform is Debian-based
    if(EXISTS "/etc/debian_version")
        set(CPACK_GENERATOR "DEB")
    # Check if the platform is Redhat-based
    elseif(EXISTS "/etc/redhat-release")
        set(CPACK_GENERATOR "RPM")
    # Otherwise, use TGZ
    else()
        set(CPACK_GENERATOR "TGZ")
    endif()
else()
    set(CPACK_GENERATOR "ZIP")
endif()

set(CPACK_PACKAGE_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/packages")
include(CPack)
