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
include boringssl/decrepit/bio/CMakeFiles/bio_decrepit.dir/depend.make

# Include the progress variables for this target.
include boringssl/decrepit/bio/CMakeFiles/bio_decrepit.dir/progress.make

# Include the compile flags for this target's objects.
include boringssl/decrepit/bio/CMakeFiles/bio_decrepit.dir/flags.make

boringssl/decrepit/bio/CMakeFiles/bio_decrepit.dir/base64_bio.c.o: boringssl/decrepit/bio/CMakeFiles/bio_decrepit.dir/flags.make
boringssl/decrepit/bio/CMakeFiles/bio_decrepit.dir/base64_bio.c.o: ../boringssl/decrepit/bio/base64_bio.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/malsabah/Desktop/QuicTor/quictor/src/simple-quic/lib/libquic/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object boringssl/decrepit/bio/CMakeFiles/bio_decrepit.dir/base64_bio.c.o"
	cd /home/malsabah/Desktop/QuicTor/quictor/src/simple-quic/lib/libquic/build/boringssl/decrepit/bio && /usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/bio_decrepit.dir/base64_bio.c.o   -c /home/malsabah/Desktop/QuicTor/quictor/src/simple-quic/lib/libquic/boringssl/decrepit/bio/base64_bio.c

boringssl/decrepit/bio/CMakeFiles/bio_decrepit.dir/base64_bio.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/bio_decrepit.dir/base64_bio.c.i"
	cd /home/malsabah/Desktop/QuicTor/quictor/src/simple-quic/lib/libquic/build/boringssl/decrepit/bio && /usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/malsabah/Desktop/QuicTor/quictor/src/simple-quic/lib/libquic/boringssl/decrepit/bio/base64_bio.c > CMakeFiles/bio_decrepit.dir/base64_bio.c.i

boringssl/decrepit/bio/CMakeFiles/bio_decrepit.dir/base64_bio.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/bio_decrepit.dir/base64_bio.c.s"
	cd /home/malsabah/Desktop/QuicTor/quictor/src/simple-quic/lib/libquic/build/boringssl/decrepit/bio && /usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/malsabah/Desktop/QuicTor/quictor/src/simple-quic/lib/libquic/boringssl/decrepit/bio/base64_bio.c -o CMakeFiles/bio_decrepit.dir/base64_bio.c.s

boringssl/decrepit/bio/CMakeFiles/bio_decrepit.dir/base64_bio.c.o.requires:

.PHONY : boringssl/decrepit/bio/CMakeFiles/bio_decrepit.dir/base64_bio.c.o.requires

boringssl/decrepit/bio/CMakeFiles/bio_decrepit.dir/base64_bio.c.o.provides: boringssl/decrepit/bio/CMakeFiles/bio_decrepit.dir/base64_bio.c.o.requires
	$(MAKE) -f boringssl/decrepit/bio/CMakeFiles/bio_decrepit.dir/build.make boringssl/decrepit/bio/CMakeFiles/bio_decrepit.dir/base64_bio.c.o.provides.build
.PHONY : boringssl/decrepit/bio/CMakeFiles/bio_decrepit.dir/base64_bio.c.o.provides

boringssl/decrepit/bio/CMakeFiles/bio_decrepit.dir/base64_bio.c.o.provides.build: boringssl/decrepit/bio/CMakeFiles/bio_decrepit.dir/base64_bio.c.o


bio_decrepit: boringssl/decrepit/bio/CMakeFiles/bio_decrepit.dir/base64_bio.c.o
bio_decrepit: boringssl/decrepit/bio/CMakeFiles/bio_decrepit.dir/build.make

.PHONY : bio_decrepit

# Rule to build all files generated by this target.
boringssl/decrepit/bio/CMakeFiles/bio_decrepit.dir/build: bio_decrepit

.PHONY : boringssl/decrepit/bio/CMakeFiles/bio_decrepit.dir/build

boringssl/decrepit/bio/CMakeFiles/bio_decrepit.dir/requires: boringssl/decrepit/bio/CMakeFiles/bio_decrepit.dir/base64_bio.c.o.requires

.PHONY : boringssl/decrepit/bio/CMakeFiles/bio_decrepit.dir/requires

boringssl/decrepit/bio/CMakeFiles/bio_decrepit.dir/clean:
	cd /home/malsabah/Desktop/QuicTor/quictor/src/simple-quic/lib/libquic/build/boringssl/decrepit/bio && $(CMAKE_COMMAND) -P CMakeFiles/bio_decrepit.dir/cmake_clean.cmake
.PHONY : boringssl/decrepit/bio/CMakeFiles/bio_decrepit.dir/clean

boringssl/decrepit/bio/CMakeFiles/bio_decrepit.dir/depend:
	cd /home/malsabah/Desktop/QuicTor/quictor/src/simple-quic/lib/libquic/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/malsabah/Desktop/QuicTor/quictor/src/simple-quic/lib/libquic /home/malsabah/Desktop/QuicTor/quictor/src/simple-quic/lib/libquic/boringssl/decrepit/bio /home/malsabah/Desktop/QuicTor/quictor/src/simple-quic/lib/libquic/build /home/malsabah/Desktop/QuicTor/quictor/src/simple-quic/lib/libquic/build/boringssl/decrepit/bio /home/malsabah/Desktop/QuicTor/quictor/src/simple-quic/lib/libquic/build/boringssl/decrepit/bio/CMakeFiles/bio_decrepit.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : boringssl/decrepit/bio/CMakeFiles/bio_decrepit.dir/depend
