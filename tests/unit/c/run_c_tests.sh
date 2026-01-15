#!/bin/bash
# C unit test runner script

set -e

echo "Building and running C unit tests with Unity framework..."

# Create build directory
mkdir -p build
cd build

# Configure with CMake
cmake .. -DCMAKE_BUILD_TYPE=Debug

# Build all tests
make -j$(nproc)

# Run all tests
echo "Running C unit tests..."
ctest --verbose --output-on-failure

# Generate test report
echo "Generating test report..."
ctest --output-junit test_results.xml

echo "C unit tests completed!"
echo "Test results saved to build/test_results.xml"