option(SUBMODULE_CHECK "Enables checking that vendored library submodules are up to date" ON)
if(SUBMODULE_CHECK)
  find_package(Git)
  if(GIT_FOUND)
    function(check_submodule relative_path)
      execute_process(COMMAND git rev-parse "HEAD" WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/${relative_path} OUTPUT_VARIABLE localHead)
      execute_process(COMMAND git rev-parse "HEAD:external/${relative_path}" WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR} OUTPUT_VARIABLE checkedHead)
      string(COMPARE EQUAL "${localHead}" "${checkedHead}" upToDate)
      if (upToDate)
        message(STATUS "Submodule 'external/${relative_path}' is up-to-date")
      else()
        message(FATAL_ERROR "Submodule 'external/${relative_path}' is not up-to-date. Please update with\ngit submodule update --init --recursive\nor run cmake with -DSUBMODULE_CHECK=OFF")
      endif()

      # Extra arguments check nested submodules
      foreach(submod ${ARGN})
        execute_process(COMMAND git rev-parse "HEAD" WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/${relative_path}/${submod} OUTPUT_VARIABLE localHead)
        execute_process(COMMAND git rev-parse "HEAD:${submod}" WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/${relative_path} OUTPUT_VARIABLE checkedHead)
        string(COMPARE EQUAL "${localHead}" "${checkedHead}" upToDate)
        if (NOT upToDate)
            message(FATAL_ERROR "Nested submodule '${relative_path}/${submod}' is not up-to-date. Please update with\ngit submodule update --init --recursive\nor run cmake with -DSUBMODULE_CHECK=OFF")
        endif()
      endforeach()
    endfunction ()

    message(STATUS "Checking submodules")
    check_submodule(CLI11)
    check_submodule(nlohmann)
    check_submodule(oxen-libquic)
    check_submodule(oxen-mq)
    check_submodule(pybind11)
    check_submodule(sqlite_orm)
    check_submodule(mlkem-native)
  endif()
endif()

macro(system_or_submodule BIGNAME smallname target pkgconf subdir)
  if(NOT TARGET ${target})
    option(FORCE_${BIGNAME}_SUBMODULE "force using ${smallname} submodule" OFF)
    if(NOT BUILD_STATIC_DEPS AND NOT FORCE_${BIGNAME}_SUBMODULE AND NOT FORCE_ALL_SUBMODULES)
      pkg_check_modules(${BIGNAME} ${pkgconf} IMPORTED_TARGET)
    endif()
    if(${BIGNAME}_FOUND)
      add_library(${smallname} INTERFACE)
      if(NOT TARGET PkgConfig::${BIGNAME} AND CMAKE_VERSION VERSION_LESS "3.21")
        # Work around cmake bug 22180 (PkgConfig::THING not set if no flags needed)
      else()
        target_link_libraries(${smallname} INTERFACE PkgConfig::${BIGNAME})
      endif()
      message(STATUS "Found system ${smallname} ${${BIGNAME}_VERSION}")
    else()
      message(STATUS "using ${smallname} submodule ${subdir}")
      add_subdirectory(${subdir} EXCLUDE_FROM_ALL)
    endif()
    if(NOT TARGET ${target})
      add_library(${target} ALIAS ${smallname})
    endif()
  endif()
endmacro()

system_or_submodule(OXENC oxenc oxenc::oxenc liboxenc>=1.5.0 oxen-libquic/external/oxen-encoding)

# oxen-logging
if (NOT TARGET oxen::logging)
    if(BUILD_STATIC_DEPS)
        set(OXEN_LOGGING_FORCE_SUBMODULES ON CACHE INTERNAL "")
    endif()
    system_or_submodule(OXENLOGGING oxen-logging oxen::logging-base liboxen-logging>=1.2.0 oxen-libquic/external/oxen-logging)
    if(OXENLOGGING_FOUND)
        # If we load oxen-logging via system lib then we won't necessarily have fmt/spdlog targets,
        # but this script will give us them:
        include(oxen-libquic/external/oxen-logging/cmake/load_fmt_spdlog.cmake)

        add_library(oxen-logging-fmt-spdlog INTERFACE)
        target_link_libraries(oxen-logging-fmt-spdlog INTERFACE oxen-logging ${OXEN_LOGGING_FMT_TARGET} ${OXEN_LOGGING_SPDLOG_TARGET})
        add_library(oxen::logging ALIAS oxen-logging-fmt-spdlog)
    endif()
endif()

if(SROUTER_FULL)
    system_or_submodule(OXENMQ oxenmq oxenmq::oxenmq liboxenmq>=1.3 oxen-mq)
endif()

set(JSON_BuildTests OFF CACHE INTERNAL "")
set(JSON_Install OFF CACHE INTERNAL "")
system_or_submodule(NLOHMANN nlohmann_json nlohmann_json::nlohmann_json nlohmann_json>=3.7.0 nlohmann)


if(SROUTER_HIVE)
  add_subdirectory(pybind11 EXCLUDE_FROM_ALL)
endif()


system_or_submodule(CLI11 CLI11 CLI11::CLI11 CLI11>=2.5.0 CLI11)


if(SROUTER_PEERSTATS)
  add_library(sqlite_orm INTERFACE)
  target_include_directories(sqlite_orm SYSTEM INTERFACE sqlite_orm/include)
  if(NOT TARGET sqlite3)
    add_library(sqlite3 INTERFACE)
    pkg_check_modules(SQLITE3 REQUIRED IMPORTED_TARGET sqlite3)
    target_link_libraries(sqlite3 INTERFACE PkgConfig::SQLITE3)
  endif()
  target_link_libraries(sqlite_orm INTERFACE sqlite3)
endif()


set(LIBQUIC_BUILD_TESTS OFF CACHE BOOL "")
system_or_submodule(OXENQUIC quic oxen::quic liboxenquic>=1.8.0 oxen-libquic)


# libcrypt defaults, only on with macos and non static linux
set(default_libcrypt OFF)

if(CMAKE_SYSTEM_NAME MATCHES "Linux" AND NOT STATIC_LINK)
  pkg_check_modules(LIBCRYPT libcrypt IMPORTED_TARGET)
  if(LIBCRYPT_FOUND)
      set(default_libcrypt ON)
  endif()
endif()
if(MACOS)
  set(default_libcrypt ON)
endif()

option(WITH_LIBCRYPT "enable fast password hash with libcrypt" ${default_libcrypt})

add_library(session-router-libcrypt INTERFACE)
if(WITH_LIBCRYPT)
  pkg_check_modules(LIBCRYPT libcrypt IMPORTED_TARGET REQUIRED)
  target_compile_definitions(session-router-libcrypt INTERFACE SROUTER_HAVE_CRYPT)
  target_link_libraries(session-router-libcrypt INTERFACE PkgConfig::LIBCRYPT)
  message(STATUS "using libcrypt ${LIBCRYPT_VERSION}")
else()
  # TODO static build lib crypt?
  message(STATUS "not building with libcrypt")
endif()


if(NOT TARGET mlkem_native::mlkem768)
    file(GLOB_RECURSE mlkem_sources mlkem-native/mlkem/src/*.c mlkem-native/mlkem/src/*.S)

    add_library(mlkem_native768 STATIC ${mlkem_sources})

    target_compile_definitions(mlkem_native768 PUBLIC
        MLK_CONFIG_NO_RANDOMIZED_API
        MLK_CONFIG_PARAMETER_SET=768
        MLK_CONFIG_NAMESPACE_PREFIX=sr_mlkem768
        MLK_CONFIG_NO_SUPERCOP
        MLK_CONFIG_USE_NATIVE_BACKEND_ARITH
        MLK_CONFIG_USE_NATIVE_BACKEND_FIPS202
    )

    target_include_directories(mlkem_native768 PUBLIC mlkem-native/mlkem)

    add_library(mlkem_native::mlkem768 ALIAS mlkem_native768)
endif()
