# Runs the host example and compares its output with the transcript in docs/quickstart.md (the first ```text block),
# so the page shows what the example prints.
#   cmake -DEXE=<se05x_host_example> -DDOC=<docs/quickstart.md> -P check_example_output.cmake
execute_process(COMMAND "${EXE}" OUTPUT_VARIABLE out RESULT_VARIABLE rc)
if(NOT rc EQUAL 0)
  message(FATAL_ERROR "the host example exited with ${rc}")
endif()
file(READ "${DOC}" doc)
string(FIND "${doc}" "```text\n" start)
if(start EQUAL -1)
  message(FATAL_ERROR "no ```text block in ${DOC}")
endif()
math(EXPR start "${start} + 8")
string(SUBSTRING "${doc}" ${start} -1 rest)
string(FIND "${rest}" "```" stop)
string(SUBSTRING "${rest}" 0 ${stop} expected)
if(NOT out STREQUAL expected)
  message(FATAL_ERROR "docs/quickstart.md shows other output than the example prints:\n${out}")
endif()
