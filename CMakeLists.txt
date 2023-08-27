cmake_minimum_required(VERSION 3.10)

project(PaperGoLib VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 11)

# Абсолютный путь к исходникам Go
set(GO_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/sources")

# Установите путь для сохранения созданной библиотеки
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/shared)


if (UNIX AND NOT APPLE)
    set(LIB_EXTENSION "lib.so")
elseif (APPLE)
    set(LIB_EXTENSION "lib.dylib")
elseif (WIN32 OR WIN64)
    set(LIB_EXTENSION "lib.dll")
else ()
    message(FATAL_ERROR "Unsupported platform")
endif()


# Выполняем команду сборки в указанной директории
execute_process(
    COMMAND go build -o ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/${LIB_EXTENSION} -buildmode=c-shared ${GO_SOURCE_DIR}
    WORKING_DIRECTORY ${GO_SOURCE_DIR}  # Используем абсолютный путь к исходникам Go
    RESULT_VARIABLE GO_BUILD_RESULT)    # Сохраняем результат выполнения команды

if (GO_BUILD_RESULT EQUAL 0)
    message("Go library build successful")
else ()
    message(FATAL_ERROR "Command: ${GO_BUILD_CMD} \n returned error: ${GO_BUILD_RESULT}")
endif ()