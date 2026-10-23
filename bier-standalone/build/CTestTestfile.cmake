# CMake generated Testfile for 
# Source directory: /workspace/bier-standalone
# Build directory: /workspace/bier-standalone/build
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test(bier_unit "/workspace/bier-standalone/build/test_bier")
set_tests_properties(bier_unit PROPERTIES  _BACKTRACE_TRIPLES "/workspace/bier-standalone/CMakeLists.txt;31;add_test;/workspace/bier-standalone/CMakeLists.txt;0;")
add_test(bier_e2e "/root/.pyenv/shims/python3" "/workspace/bier-standalone/tests/e2e_udp.py" "/workspace/bier-standalone/build/bierd" "/workspace/bier-standalone/configs/example.json")
set_tests_properties(bier_e2e PROPERTIES  TIMEOUT "20" _BACKTRACE_TRIPLES "/workspace/bier-standalone/CMakeLists.txt;35;add_test;/workspace/bier-standalone/CMakeLists.txt;0;")
