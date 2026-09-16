# Unit tests that link mixnet sources directly, with the framework stubbed
# out. These are plain C executables with their own main(), so they are built
# separately from the orchestrator-driven testcases in cp1/ and cp2/.
file(GLOB files "test_*.c")
foreach(file ${files})
    get_filename_component(test ${file} NAME_WE)
    add_executable(${test} ${file})

    set_target_properties(${test}
        PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin/unit"
    )
endforeach()
