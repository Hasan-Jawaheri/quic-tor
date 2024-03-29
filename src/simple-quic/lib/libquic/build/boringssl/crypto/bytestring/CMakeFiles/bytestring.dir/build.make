# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.5

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/malsabah/Desktop/QuicTor/quictor/src/simple-quic/lib/libquic

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/malsabah/Desktop/QuicTor/quictor/src/simple-quic/lib/libquic/build

# Include any dependencies generated for this target.
include boringssl/crypto/bytestring/CMakeFiles/bytestring.dir/depend.make

# Include the progress variables for this target.
include boringssl/crypto/bytestring/CMakeFiles/bytestring.dir/progress.make

# Include the compile flags for this target's objects.
include boringssl/crypto/bytestring/CMakeFiles/bytestring.dir/flags.make

boringssl/crypto/bytestring/CMakeFiles/bytestring.dir/ber.c.o: boringssl/crypto/bytestring/CMakeFiles/bytestring.dir/flags.make
boringssl/crypto/bytestring/CMakeFiles/bytestring.dir/ber.c.o: ../boringssl/crypto/bytestring/ber.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/malsabah/Desktop/QuicTor/quictor/src/simple-quic/lib/libquic/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object boringssl/crypto/bytestring/CMakeFiles/bytestring.dir/ber.c.o"
	cd /home/malsabah/Desktop/QuicTor/quictor/src/simple-quic/lib/libquic/build/boringssl/crypto/bytestring && /usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/bytestring.dir/ber.c.o   -c /home/malsabah/Desktop/QuicTor/quictor/src/simple-quic/lib/libquic/boringssl/crypto/bytestring/ber.c

boringssl/crypto/bytestring/CMakeFiles/bytestring.dir/ber.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/bytestring.dir/ber.c.i"
	cd /home/malsabah/Desktop/QuicTor/quictor/src/simple-quic/lib/libquic/build/boringssl/crypto/bytestring && /usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/malsabah/Desktop/QuicTor/quictor/src/simple-quic/lib/libquic/boringssl/crypto/bytestring/ber.c > CMakeFiles/bytestring.dir/ber.c.i

boringssl/crypto/bytestring/CMakeFiles/bytestring.dir/ber.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/bytestring.dir/ber.c.s"
	cd /home/malsabah/Desktop/QuicTor/quictor/src/simple-quic/lib/libquic/build/boringssl/crypto/bytestring && /usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/malsabah/Desktop/QuicTor/quictor/src/simple-quic/lib/libquic/boringssl/crypto/bytestring/ber.c -o CMakeFiles/bytestring.dir/ber.c.s

boringssl/crypto/bytestring/CMakeFiles/bytestring.dir/ber.c.o.requires:

.PHONY : boringssl/crypto/bytestring/CMakeFiles/bytestring.dir/ber.c.o.requires

boringssl/crypto/bytestring/CMakeFiles/bytestring.dir/ber.c.o.provides: boringssl/crypto/bytestring/CMakeFiles/bytestring.dir/ber.c.o.requires
	$(MAKE) -f boringssl/crypto/bytestring/CMakeFiles/bytestring.dir/build.make boringssl/crypto/bytestring/CMakeFiles/bytestring.dir/ber.c.o.provides.build
.PHONY : boringssl/crypto/bytestring/CMakeFiles/bytestring.dir/ber.c.o.provides

boringssl/crypto/bytestring/CMakeFiles/bytestring.dir/ber.c.o.provides.build: boringssl/crypto/bytestring/CMakeFiles/bytestring.dir/ber.c.o


boringssl/crypto/bytestring/CMakeFiles/bytestring.dir/cbs.c.o: boringssl/crypto/bytestring/CMakeFiles/bytestring.dir/flags.make
boringssl/crypto/bytestring/CMakeFiles/bytestring.dir/cbs.c.o: ../boringssl/crypto/bytestring/cbs.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/malsabah/Desktop/QuicTor/quictor/src/simple-quic/lib/libquic/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building C object boringssl/crypto/bytestring/CMakeFiles/bytestring.dir/cbs.c.o"
	cd /home/malsabah/Desktop/QuicTor/quictor/src/simple-quic/lib/libquic/build/boringssl/crypto/bytestring && /usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/bytestring.dir/cbs.c.o   -c /home/malsabah/Desktop/QuicTor/quictor/src/simple-quic/lib/libquic/boringssl/crypto/bytestring/cbs.c

boringssl/crypto/bytestring/CMakeFiles/bytestring.dir/cbs.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/bytestring.dir/cbs.c.i"
	cd /home/malsabah/Desktop/QuicTor/quictor/src/simple-quic/lib/libquic/build/boringssl/crypto/bytestring && /usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/malsabah/Desktop/QuicTor/quictor/src/simple-quic/lib/libquic/boringssl/crypto/bytestring/cbs.c > CMakeFiles/bytestring.dir/cbs.c.i

boringssl/crypto/bytestring/CMakeFiles/bytestring.dir/cbs.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/bytestring.dir/cbs.c.s"
	cd /home/malsabah/Desktop/QuicTor/quictor/src/simple-quic/lib/libquic/build/boringssl/crypto/bytestring && /usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/malsabah/Desktop/QuicTor/quictor/src/simple-quic/lib/libquic/boringssl/crypto/bytestring/cbs.c -o CMakeFiles/bytestring.dir/cbs.c.s

boringssl/crypto/bytestring/CMakeFiles/bytestring.dir/cbs.c.o.requires:

.PHONY : boringssl/crypto/bytestring/CMakeFiles/bytestring.dir/cbs.c.o.requires

boringssl/crypto/bytestring/CMakeFiles/bytestring.dir/cbs.c.o.provides: boringssl/crypto/bytestring/CMakeFiles/bytestring.dir/cbs.c.o.requires
	$(MAKE) -f boringssl/crypto/bytestring/CMakeFiles/bytestring.dir/build.make boringssl/crypto/bytestring/CMakeFiles/bytestring.dir/cbs.c.o.provides.build
.PHONY : boringssl/crypto/bytestring/CMakeFiles/bytestring.dir/cbs.c.o.provides

boringssl/crypto/bytestring/CMakeFiles/bytestring.dir/cbs.c.o.provides.build: boringssl/crypto/bytestring/CMakeFiles/bytestring.dir/cbs.c.o


boringssl/crypto/bytestring/CMakeFiles/bytestring.dir/cbb.c.o: boringssl/crypto/bytestring/CMakeFiles/bytestring.dir/flags.make
boringssl/crypto/bytestring/CMakeFiles/bytestring.dir/cbb.c.o: ../boringssl/crypto/bytestring/cbb.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/malsabah/Desktop/QuicTor/quictor/src/simple-quic/lib/libquic/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building C object boringssl/crypto/bytestring/CMakeFiles/bytestring.dir/cbb.c.o"
	cd /home/malsabah/Desktop/QuicTor/quictor/src/simple-quic/lib/libquic/build/boringssl/crypto/bytestring && /usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/bytestring.dir/cbb.c.o   -c /home/malsabah/Desktop/QuicTor/quictor/src/simple-quic/lib/libquic/boringssl/crypto/bytestring/cbb.c

boringssl/crypto/bytestring/CMakeFiles/bytestring.dir/cbb.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/bytestring.dir/cbb.c.i"
	cd /home/malsabah/Desktop/QuicTor/quictor/src/simple-quic/lib/libquic/build/boringssl/crypto/bytestring && /usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/malsabah/Desktop/QuicTor/quictor/src/simple-quic/lib/libquic/boringssl/crypto/bytestring/cbb.c > CMakeFiles/bytestring.dir/cbb.c.i

boringssl/crypto/bytestring/CMakeFiles/bytestring.dir/cbb.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/bytestring.dir/cbb.c.s"
	cd /home/malsabah/Desktop/QuicTor/quictor/src/simple-quic/lib/libquic/build/boringssl/crypto/bytestring && /usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/malsabah/Desktop/QuicTor/quictor/src/simple-quic/lib/libquic/boringssl/crypto/bytestring/cbb.c -o CMakeFiles/bytestring.dir/cbb.c.s

boringssl/crypto/bytestring/CMakeFiles/bytestring.dir/cbb.c.o.requires:

.PHONY : boringssl/crypto/bytestring/CMakeFiles/bytestring.dir/cbb.c.o.requires

boringssl/crypto/bytestring/CMakeFiles/bytestring.dir/cbb.c.o.provides: boringssl/crypto/bytestring/CMakeFiles/bytestring.dir/cbb.c.o.requires
	$(MAKE) -f boringssl/crypto/bytestring/CMakeFiles/bytestring.dir/build.make boringssl/crypto/bytestring/CMakeFiles/bytestring.dir/cbb.c.o.provides.build
.PHONY : boringssl/crypto/bytestring/CMakeFiles/bytestring.dir/cbb.c.o.provides

boringssl/crypto/bytestring/CMakeFiles/bytestring.dir/cbb.c.o.provides.build: boringssl/crypto/bytestring/CMakeFiles/bytestring.dir/cbb.c.o


bytestring: boringssl/crypto/bytestring/CMakeFiles/bytestring.dir/ber.c.o
bytestring: boringssl/crypto/bytestring/CMakeFiles/bytestring.dir/cbs.c.o
bytestring: boringssl/crypto/bytestring/CMakeFiles/bytestring.dir/cbb.c.o
bytestring: boringssl/crypto/bytestring/CMakeFiles/bytestring.dir/build.make

.PHONY : bytestring

# Rule to build all files generated by this target.
boringssl/crypto/bytestring/CMakeFiles/bytestring.dir/build: bytestring

.PHONY : boringssl/crypto/bytestring/CMakeFiles/bytestring.dir/build

boringssl/crypto/bytestring/CMakeFiles/bytestring.dir/requires: boringssl/crypto/bytestring/CMakeFiles/bytestring.dir/ber.c.o.requires
boringssl/crypto/bytestring/CMakeFiles/bytestring.dir/requires: boringssl/crypto/bytestring/CMakeFiles/bytestring.dir/cbs.c.o.requires
boringssl/crypto/bytestring/CMakeFiles/bytestring.dir/requires: boringssl/crypto/bytestring/CMakeFiles/bytestring.dir/cbb.c.o.requires

.PHONY : boringssl/crypto/bytestring/CMakeFiles/bytestring.dir/requires

boringssl/crypto/bytestring/CMakeFiles/bytestring.dir/clean:
	cd /home/malsabah/Desktop/QuicTor/quictor/src/simple-quic/lib/libquic/build/boringssl/crypto/bytestring && $(CMAKE_COMMAND) -P CMakeFiles/bytestring.dir/cmake_clean.cmake
.PHONY : boringssl/crypto/bytestring/CMakeFiles/bytestring.dir/clean

boringssl/crypto/bytestring/CMakeFiles/bytestring.dir/depend:
	cd /home/malsabah/Desktop/QuicTor/quictor/src/simple-quic/lib/libquic/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/malsabah/Desktop/QuicTor/quictor/src/simple-quic/lib/libquic /home/malsabah/Desktop/QuicTor/quictor/src/simple-quic/lib/libquic/boringssl/crypto/bytestring /home/malsabah/Desktop/QuicTor/quictor/src/simple-quic/lib/libquic/build /home/malsabah/Desktop/QuicTor/quictor/src/simple-quic/lib/libquic/build/boringssl/crypto/bytestring /home/malsabah/Desktop/QuicTor/quictor/src/simple-quic/lib/libquic/build/boringssl/crypto/bytestring/CMakeFiles/bytestring.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : boringssl/crypto/bytestring/CMakeFiles/bytestring.dir/depend

