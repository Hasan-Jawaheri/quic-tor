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
include boringssl/crypto/digest/CMakeFiles/digest.dir/depend.make

# Include the progress variables for this target.
include boringssl/crypto/digest/CMakeFiles/digest.dir/progress.make

# Include the compile flags for this target's objects.
include boringssl/crypto/digest/CMakeFiles/digest.dir/flags.make

boringssl/crypto/digest/CMakeFiles/digest.dir/digest.c.o: boringssl/crypto/digest/CMakeFiles/digest.dir/flags.make
boringssl/crypto/digest/CMakeFiles/digest.dir/digest.c.o: ../boringssl/crypto/digest/digest.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/malsabah/Desktop/QuicTor/quictor/src/simple-quic/lib/libquic/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object boringssl/crypto/digest/CMakeFiles/digest.dir/digest.c.o"
	cd /home/malsabah/Desktop/QuicTor/quictor/src/simple-quic/lib/libquic/build/boringssl/crypto/digest && /usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/digest.dir/digest.c.o   -c /home/malsabah/Desktop/QuicTor/quictor/src/simple-quic/lib/libquic/boringssl/crypto/digest/digest.c

boringssl/crypto/digest/CMakeFiles/digest.dir/digest.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/digest.dir/digest.c.i"
	cd /home/malsabah/Desktop/QuicTor/quictor/src/simple-quic/lib/libquic/build/boringssl/crypto/digest && /usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/malsabah/Desktop/QuicTor/quictor/src/simple-quic/lib/libquic/boringssl/crypto/digest/digest.c > CMakeFiles/digest.dir/digest.c.i

boringssl/crypto/digest/CMakeFiles/digest.dir/digest.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/digest.dir/digest.c.s"
	cd /home/malsabah/Desktop/QuicTor/quictor/src/simple-quic/lib/libquic/build/boringssl/crypto/digest && /usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/malsabah/Desktop/QuicTor/quictor/src/simple-quic/lib/libquic/boringssl/crypto/digest/digest.c -o CMakeFiles/digest.dir/digest.c.s

boringssl/crypto/digest/CMakeFiles/digest.dir/digest.c.o.requires:

.PHONY : boringssl/crypto/digest/CMakeFiles/digest.dir/digest.c.o.requires

boringssl/crypto/digest/CMakeFiles/digest.dir/digest.c.o.provides: boringssl/crypto/digest/CMakeFiles/digest.dir/digest.c.o.requires
	$(MAKE) -f boringssl/crypto/digest/CMakeFiles/digest.dir/build.make boringssl/crypto/digest/CMakeFiles/digest.dir/digest.c.o.provides.build
.PHONY : boringssl/crypto/digest/CMakeFiles/digest.dir/digest.c.o.provides

boringssl/crypto/digest/CMakeFiles/digest.dir/digest.c.o.provides.build: boringssl/crypto/digest/CMakeFiles/digest.dir/digest.c.o


boringssl/crypto/digest/CMakeFiles/digest.dir/digests.c.o: boringssl/crypto/digest/CMakeFiles/digest.dir/flags.make
boringssl/crypto/digest/CMakeFiles/digest.dir/digests.c.o: ../boringssl/crypto/digest/digests.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/malsabah/Desktop/QuicTor/quictor/src/simple-quic/lib/libquic/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building C object boringssl/crypto/digest/CMakeFiles/digest.dir/digests.c.o"
	cd /home/malsabah/Desktop/QuicTor/quictor/src/simple-quic/lib/libquic/build/boringssl/crypto/digest && /usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/digest.dir/digests.c.o   -c /home/malsabah/Desktop/QuicTor/quictor/src/simple-quic/lib/libquic/boringssl/crypto/digest/digests.c

boringssl/crypto/digest/CMakeFiles/digest.dir/digests.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/digest.dir/digests.c.i"
	cd /home/malsabah/Desktop/QuicTor/quictor/src/simple-quic/lib/libquic/build/boringssl/crypto/digest && /usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/malsabah/Desktop/QuicTor/quictor/src/simple-quic/lib/libquic/boringssl/crypto/digest/digests.c > CMakeFiles/digest.dir/digests.c.i

boringssl/crypto/digest/CMakeFiles/digest.dir/digests.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/digest.dir/digests.c.s"
	cd /home/malsabah/Desktop/QuicTor/quictor/src/simple-quic/lib/libquic/build/boringssl/crypto/digest && /usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/malsabah/Desktop/QuicTor/quictor/src/simple-quic/lib/libquic/boringssl/crypto/digest/digests.c -o CMakeFiles/digest.dir/digests.c.s

boringssl/crypto/digest/CMakeFiles/digest.dir/digests.c.o.requires:

.PHONY : boringssl/crypto/digest/CMakeFiles/digest.dir/digests.c.o.requires

boringssl/crypto/digest/CMakeFiles/digest.dir/digests.c.o.provides: boringssl/crypto/digest/CMakeFiles/digest.dir/digests.c.o.requires
	$(MAKE) -f boringssl/crypto/digest/CMakeFiles/digest.dir/build.make boringssl/crypto/digest/CMakeFiles/digest.dir/digests.c.o.provides.build
.PHONY : boringssl/crypto/digest/CMakeFiles/digest.dir/digests.c.o.provides

boringssl/crypto/digest/CMakeFiles/digest.dir/digests.c.o.provides.build: boringssl/crypto/digest/CMakeFiles/digest.dir/digests.c.o


digest: boringssl/crypto/digest/CMakeFiles/digest.dir/digest.c.o
digest: boringssl/crypto/digest/CMakeFiles/digest.dir/digests.c.o
digest: boringssl/crypto/digest/CMakeFiles/digest.dir/build.make

.PHONY : digest

# Rule to build all files generated by this target.
boringssl/crypto/digest/CMakeFiles/digest.dir/build: digest

.PHONY : boringssl/crypto/digest/CMakeFiles/digest.dir/build

boringssl/crypto/digest/CMakeFiles/digest.dir/requires: boringssl/crypto/digest/CMakeFiles/digest.dir/digest.c.o.requires
boringssl/crypto/digest/CMakeFiles/digest.dir/requires: boringssl/crypto/digest/CMakeFiles/digest.dir/digests.c.o.requires

.PHONY : boringssl/crypto/digest/CMakeFiles/digest.dir/requires

boringssl/crypto/digest/CMakeFiles/digest.dir/clean:
	cd /home/malsabah/Desktop/QuicTor/quictor/src/simple-quic/lib/libquic/build/boringssl/crypto/digest && $(CMAKE_COMMAND) -P CMakeFiles/digest.dir/cmake_clean.cmake
.PHONY : boringssl/crypto/digest/CMakeFiles/digest.dir/clean

boringssl/crypto/digest/CMakeFiles/digest.dir/depend:
	cd /home/malsabah/Desktop/QuicTor/quictor/src/simple-quic/lib/libquic/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/malsabah/Desktop/QuicTor/quictor/src/simple-quic/lib/libquic /home/malsabah/Desktop/QuicTor/quictor/src/simple-quic/lib/libquic/boringssl/crypto/digest /home/malsabah/Desktop/QuicTor/quictor/src/simple-quic/lib/libquic/build /home/malsabah/Desktop/QuicTor/quictor/src/simple-quic/lib/libquic/build/boringssl/crypto/digest /home/malsabah/Desktop/QuicTor/quictor/src/simple-quic/lib/libquic/build/boringssl/crypto/digest/CMakeFiles/digest.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : boringssl/crypto/digest/CMakeFiles/digest.dir/depend
