cmake_minimum_required(VERSION 3.16)

project(encryptool LANGUAGES CXX C)
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD_EXTENSION OFF)

# Enable extra find_package modules
set(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake/modules)

# Find the library
# find_package(Boost REQURIED COMPONENTS system)

# Set up the executable target
add_executable(${PROJECT_NAME} main.cpp)

# Set include dirs
target_include_directories(${PROJECT_NAME}
    PUBLIC
        $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
    PRIVATE
        ${PROJECT_SOURCE_DIR}/src
)

# Link to thirdparty libraries
# target_link_libraries(${PROJECT_NAME} PRIVATE )

include(GNUInstallDirs)
# Set up the installation 
install(TARGETS ${PROJECT_NAME} 
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    INCLUDES DESTINATION include/__PROJNAME_)

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
