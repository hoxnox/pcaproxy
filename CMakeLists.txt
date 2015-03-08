# @author $username$ <$usermail$>
# @date $date$
# pcaproxy cmake build script

cmake_minimum_required(VERSION 2.6.4)

########################################################################
# options

option(WITH_TESTS           "Build tests."  OFF)
option(WITH_DOCS            "Generate docs" OFF)

# Don't download and build lib - find system's one if ON
option(WITH_SYSTEM_LIBPCAP  "Use system's libpcap" OFF)
option(WITH_SYSTEM_LIBEVENT "Use system's libevent" OFF)
option(WITH_SYSTEM_LIBNIDS  "Use system's libnids" OFF)

########################################################################
# general

project(pcaproxy)

set(pcaproxy_VERSION_MAJOR 0)
set(pcaproxy_VERSION_MINOR 0)
set(pcaproxy_VERSION_PATCH 0)
# configuration header
configure_file(
	"${PROJECT_SOURCE_DIR}/src/pcaproxy_config.cfg"
	"${PROJECT_SOURCE_DIR}/src/pcaproxy_config.h"
	ESCAPE_QUOTES
)

set(CMAKE_MODULE_PATH "${CMAKE_MODULE_PATH}"
                      "${PROJECT_SOURCE_DIR}/cmake/Modules")

include_directories("${PROJECT_SOURCE_DIR}/src")
set(DEPS_ROOT "${CMAKE_CURRENT_BINARY_DIR}/deps")

########################################################################
# threads

find_package(Threads REQUIRED)

########################################################################
# libpcap

if(NOT WITH_SYSTEM_LIBPCAP)
	include(ExternalProject)
	ExternalProject_Add(libpcap
		URL "http://www.tcpdump.org/release/libpcap-1.6.2.tar.gz"
		URL_MD5 "5f14191c1a684a75532c739c2c4059fa"
		CONFIGURE_COMMAND <SOURCE_DIR>/configure --prefix <INSTALL_DIR> --disable-shared      --disable-dbus --disable-can         --disable-canusb      --disable-bluetooth --disable-universal   --disable-ipv6        --disable-protochain --disable-largefile  --without-libnl
		INSTALL_DIR "${DEPS_ROOT}"
	)
	set(Pcap_INCLUDE_DIR ${DEPS_ROOT}/include)
	set(Pcap_LIBRARIES ${DEPS_ROOT}/lib/libpcap.a)
else()
	find_package(Pcap REQUIRED)
endif()
include_directories(${Pcap_INCLUDE_DIR})

########################################################################
# libnids

if(NOT WITH_SYSTEM_NIDS)
	include(ExternalProject)
	ExternalProject_Add(libnids
		URL "http://sourceforge.net/projects/libnids/files/libnids/1.24/libnids-1.24.tar.gz/download"
		URL_MD5 "72d37c79c85615ffe158aa524d649610"
		CONFIGURE_COMMAND <SOURCE_DIR>/configure --prefix <INSTALL_DIR> --enable-static --disable-shared --disable-libglib --disable-libnet
		BINARY_DIR ${CMAKE_CURRENT_BINARY_DIR}/libnids-prefix/src/libnids
		INSTALL_DIR "${DEPS_ROOT}"
		INSTALL_COMMAND make install
		DEPENDS libpcap
	)
	set(NIDS_INCLUDE_DIR ${DEPS_ROOT}/include)
	set(NIDS_LIBRARIES ${DEPS_ROOT}/lib/libnids.a)
else()
	find_package(Event REQUIRED)
endif()
include_directories(${NIDS_INCLUDE_DIR})
list(APPEND LIBRARIES ${NIDS_LIBRARIES} ${Pcap_LIBRARIES})

########################################################################
# libevent

if(NOT WITH_SYSTEM_LIBEVENT)
	include(ExternalProject)
	ExternalProject_Add(libevent
		URL "https://github.com/libevent/libevent/archive/release-2.0.22-stable.tar.gz"
		URL_MD5 "8913ef56ec329f2c046007bd634c7201"
		PATCH_COMMAND <SOURCE_DIR>/autogen.sh
		CONFIGURE_COMMAND <SOURCE_DIR>/configure --prefix <INSTALL_DIR> --enable-static --disable-shared
		INSTALL_DIR "${DEPS_ROOT}"
	)
	set(Event_INCLUDE_DIR ${DEPS_ROOT}/include)
	set(Event_LIBRARIES ${DEPS_ROOT}/lib/libevent.a)
else()
	find_package(Event REQUIRED)
endif()
include_directories(${Event_INCLUDE_DIR})
list(APPEND LIBRARIES ${Event_LIBRARIES})

########################################################################
# NxSocket

set(NX_SOCKET_SRC
	src/utils/NxSocket.h
	src/utils/NxSocket.c
)
add_library(nx_socket STATIC ${NX_SOCKET_SRC})
if(NOT WIN32)
	list(APPEND LIBRARIES pthread)
endif()
list(APPEND LIBRARIES nx_socket)

########################################################################
# pcaproxy

add_executable(pcaproxy
	src/main.cpp

	src/ProcessManager.hpp
	src/ProcessManager.cpp
	src/Logger.hpp
	src/Logger.cpp
	src/Config.hpp
	src/Config.cpp
	src/PCAProxy.hpp
	src/PCAProxy.cpp
	src/PCAParser.hpp
	src/PCAParser.cpp

	src/utils/LogStream.hpp
	src/utils/LogStream.cpp
	src/utils/ProcessManagerBase.hpp
	src/utils/ProcessManagerBase.cpp
)
target_link_libraries(pcaproxy ${LIBRARIES})
set_target_properties(pcaproxy PROPERTIES COMPILE_FLAGS "-std=c++0x")

########################################################################
# docs

if(WITH_DOCS)
	FIND_PACKAGE(Doxygen)
	if(DOXYGEN_FOUND)
		set(ENV{pcaproxy_ROOT} "${PROJECT_SOURCE_DIR}")
		ADD_CUSTOM_TARGET(doc COMMAND ${CMAKE_COMMAND}
			-D PDIR="${PROJECT_SOURCE_DIR}"
			-P "${PROJECT_SOURCE_DIR}/doc/doxygen.cmake")
	else()
		message(WARNING
			"Doxygen not found."
			" Documentation wouldn't be ganarated")
	endif()
endif()

########################################################################
# tests

function(nx_GTEST_ADD_TESTS executable extra_args)
	foreach(source ${ARGN})
		file(READ "${source}" contents)
		string(REGEX MATCHALL "TEST_?F?\\(([A-Za-z_0-9 ,]+)\\)"
			found_tests ${contents})
		foreach(hit ${found_tests})
			string(REGEX REPLACE ".*\\( *([A-Za-z_0-9]+),"
			                     " *([A-Za-z_0-9]+) *\\).*"
			                     "\\1.\\2"
			                     test_name ${hit})
			add_test("${executable}-${test_name}"
				${executable}
				--gtest_filter=${test_name}
				${extra_args})
		endforeach()
	endforeach()
endfunction()

if(WITH_TESTS)
	set(SOURCES_TEST
		./test/test.cpp)
	enable_testing()
	find_package(GTest REQUIRED)
	include_directories(${GTEST_INCLUDE_DIRS})
	set(TEST test_${PROJECT_NAME})
	add_executable(${TEST} ${SOURCES_TEST})
	if(NOT WIN32)
		SET_TARGET_PROPERTIES(${TEST} 
			PROPERTIES LINK_FLAGS -pthread)
	endif(NOT WIN32)
	target_link_libraries("${TEST}" ${GTEST_LIBRARIES} ${LIBRARIES})
	nx_GTEST_ADD_TESTS("${TEST}" ${SOURCES_TEST})
endif()

########################################################################
# installation

set(CPACK_SET_DESTDIR ON)

install(TARGETS ${TARGETS} DESTINATION bin)
#install(FILES <files> DESTINATION <dest>)

INCLUDE(InstallRequiredSystemLibraries)

SET(CPACK_PACKAGE_DESCRIPTION_SUMMARY "pcaproxy DESC")
SET(CPACK_PACKAGE_VENDOR "ORG")
SET(CPACK_PACKAGE_DESCRIPTION_FILE
	"${CMAKE_CURRENT_SOURCE_DIR}/README.markdown")
SET(CPACK_RESOURCE_FILE_LICENSE
	"${CMAKE_CURRENT_SOURCE_DIR}/LICENSE")
SET(CPACK_PACKAGE_VERSION_MAJOR ${pcaproxy_VERSION_MAJOR})
SET(CPACK_PACKAGE_VERSION_MINOR ${pcaproxy_VERSION_MINOR})
SET(CPACK_PACKAGE_VERSION_PATCH ${pcaproxy_VERSION_PATCH})
SET(CPACK_PACKAGE_INSTALL_DIRECTORY
	"CMake ${CMake_VERSION_MAJOR}.${CMake_VERSION_MINOR}")
IF(WIN32 AND NOT UNIX)
	# NOT IMPLEMENTED
ELSE(WIN32 AND NOT UNIX)
	SET(CPACK_STRIP_FILES ${TARGETS})
	SET(CPACK_SOURCE_STRIP_FILES "")
ENDIF(WIN32 AND NOT UNIX)
#SET(CPACK_PACKAGE_EXECUTABLES "null" "null desc")

INCLUDE(CPack)

