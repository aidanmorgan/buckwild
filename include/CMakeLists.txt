# Include directory CMake configuration

# Install headers
install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/buckwild/
    DESTINATION include/buckwild
    FILES_MATCHING PATTERN "*.h"
)