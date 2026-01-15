# Static Analysis Tools Configuration
# Provides options to enable clang-tidy, cppcheck, and other static analyzers

option(ENABLE_CLANG_TIDY "Enable clang-tidy static analysis" OFF)
option(ENABLE_CPPCHECK "Enable cppcheck static analysis" OFF)

# Clang-Tidy Setup
if(ENABLE_CLANG_TIDY)
    find_program(CLANG_TIDY_EXE NAMES clang-tidy clang-tidy-14 clang-tidy-15 clang-tidy-16)

    if(CLANG_TIDY_EXE)
        message(STATUS "clang-tidy found: ${CLANG_TIDY_EXE}")

        # Set clang-tidy command with configuration
        set(CMAKE_C_CLANG_TIDY
            ${CLANG_TIDY_EXE};
            --config-file=${CMAKE_SOURCE_DIR}/.clang-tidy;
            --header-filter=${CMAKE_SOURCE_DIR}/(src|include)/.*;
        )

        # Create a separate target for running clang-tidy
        add_custom_target(clang-tidy
            COMMAND ${CMAKE_COMMAND} -E echo "Running clang-tidy analysis..."
            COMMAND find ${CMAKE_SOURCE_DIR}/src/common/c
                    -name "*.c" -o -name "*.h"
                    | xargs ${CLANG_TIDY_EXE}
                    --config-file=${CMAKE_SOURCE_DIR}/.clang-tidy
                    -p ${CMAKE_BINARY_DIR}
            WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
            COMMENT "Running clang-tidy on C sources"
        )
    else()
        message(WARNING "clang-tidy requested but not found")
    endif()
endif()

# Cppcheck Setup
if(ENABLE_CPPCHECK)
    find_program(CPPCHECK_EXE NAMES cppcheck)

    if(CPPCHECK_EXE)
        message(STATUS "cppcheck found: ${CPPCHECK_EXE}")

        set(CMAKE_C_CPPCHECK
            ${CPPCHECK_EXE};
            --enable=warning,style,performance,portability;
            --inline-suppr;
            --suppress=missingIncludeSystem;
            --error-exitcode=2;
            --std=c11;
        )

        # Create a separate target for running cppcheck
        add_custom_target(cppcheck
            COMMAND ${CPPCHECK_EXE}
                --enable=all
                --suppress=missingIncludeSystem
                --inline-suppr
                --std=c11
                --platform=unix64
                --error-exitcode=1
                -I ${CMAKE_SOURCE_DIR}/include
                ${CMAKE_SOURCE_DIR}/src/common/c
            WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
            COMMENT "Running cppcheck on C sources"
        )
    else()
        message(WARNING "cppcheck requested but not found")
    endif()
endif()

# Combined static analysis target
if(ENABLE_CLANG_TIDY OR ENABLE_CPPCHECK)
    add_custom_target(static-analysis
        COMMENT "Running all static analysis tools"
    )

    if(TARGET clang-tidy)
        add_dependencies(static-analysis clang-tidy)
    endif()

    if(TARGET cppcheck)
        add_dependencies(static-analysis cppcheck)
    endif()
endif()
