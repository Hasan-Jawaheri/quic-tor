OBJDIR=objs

LIBQUICSOCK=libquicsock.so

# Test client and server from QUIC
QUIC_SERVER_APP=quic_server
QUIC_CLIENT_APP=quic_client

# Client and server made with libquicsock
QUICSOCK_SERVER=quicsock_server
QUICSOCK_CLIENT=quicsock_client

default: $(LIBQUICSOCK)

# For compiling C++ (QUIC code)
CXX = g++ -m64 -std=c++11
CXXFLAGS = -I. -Ilib/libquic/src/third_party/protobuf/src -Ilib/libquic/src -Ichromium -O3 -Wall -DOS_POSIX -fpic -g -DNDEBUG

# For compiling C (quicsock bin)
CC = gcc -m64
CCFLAGS = -I. -O3 -Wall -fpic -g -DNDEBUG

# Flags for compiling libquic
LIBQUIC_CMAKE_FLAGS = -DCMAKE_BUILD_TYPE=Release

# Remove -DNDEBUG for debug mode.
debug: CXXFLAGS := $(filter-out -DNDEBUG,$(CXXFLAGS))
debug: LIBQUIC_CMAKE_FLAGS := $(filter-out -DCMAKE_BUILD_TYPE=Release,$(LIBQUIC_FLAGS)) -DCMAKE_BUILD_TYPE=Debug
debug: default

# Flags for using the shared library
SOFLAGS=-L. -Wl,-rpath=.

# LIBS must go before LIBQUIC during linking of libquicsock in order to ensure
# that we use OpenSSL definitions before falling back to BoringSSL.
LIBS = -pthread -levent -lssl -lcrypto

# TODO(kku): Currently we include libcrypto from boringssl and librprotbuf
# included in libquic because of version incompatibility.
# These should be replaced by OpenSSL and libprotobuf of the system.
LIBQUIC=lib/libquic/build/libquic.a lib/libquic/build/boringssl/crypto/libcrypto.a lib/libquic/build/protobuf/libprotobuf.a

.PHONY: dirs clean clean_all

dirs:
		/bin/mkdir -p $(OBJDIR)/

clean:
		/bin/rm -rf $(OBJDIR) *~ $(QUIC_SERVER_APP) $(QUIC_CLIENT_APP) $(LIBQUICSOCK) $(QUICSOCK_SERVER) $(QUICSOCK_CLIENT)

clean_all: clean
		/bin/rm -rf lib/libquic/build

SERVERSRCS := $(shell find server -type f -name '*.cc')
SERVEROBJS := $(addprefix $(OBJDIR)/, $(SERVERSRCS:.cc=.o))

CLIENTSRCS := $(shell find client -type f -name '*.cc')
CLIENTOBJS := $(addprefix $(OBJDIR)/, $(CLIENTSRCS:.cc=.o))

CHROMIUMSRCS := $(shell find chromium -type f -name '*.cc')
CHROMIUMOBJS := $(addprefix $(OBJDIR)/, $(CHROMIUMSRCS:.cc=.o))

CUSTOMSRCS := $(shell find custom -type f -name '*.cc')
CUSTOMOBJS := $(addprefix $(OBJDIR)/, $(CUSTOMSRCS:.cc=.o))

QUICSOCKSRCS := $(shell find quicsock -type f -name '*.cc')
QUICSOCKOBJS := $(addprefix $(OBJDIR)/, $(QUICSOCKSRCS:.cc=.o))

LIBQUIC_SRCS := $(shell find lib/libquic/src -type f -name '*.cc')

$(LIBQUICSOCK): dirs $(QUICSOCKOBJS) $(CHROMIUMOBJS) $(CUSTOMOBJS) $(LIBQUIC)
		$(CXX) -shared $(CXXFLAGS) -o $@ $(QUICSOCKOBJS) $(CHROMIUMOBJS) $(CUSTOMOBJS) $(LIBS) $(LIBQUIC)

$(QUIC_SERVER_APP): $(OBJDIR)/quic_server_bin.o $(SERVEROBJS) $(CHROMIUMOBJS) $(CUSTOMOBJS) $(LIBQUIC)
		$(CXX) $(CXXFLAGS) -o $@ $(OBJDIR)/quic_server_bin.o $(SERVEROBJS) $(CHROMIUMOBJS) $(CUSTOMOBJS) $(LIBS) $(LIBQUIC)

$(QUIC_CLIENT_APP): $(OBJDIR)/quic_client_bin.o $(CLIENTOBJS) $(CHROMIUMOBJS) $(CUSTOMOBJS) $(LIBQUIC)
		$(CXX) $(CXXFLAGS) -o $@ $(OBJDIR)/quic_client_bin.o $(CLIENTOBJS) $(CHROMIUMOBJS) $(CUSTOMOBJS) $(LIBS) $(LIBQUIC)

$(QUICSOCK_SERVER): $(OBJDIR)/quicsock_server_bin.o $(LIBQUICSOCK)
		$(CC) $(CCFLAGS) $(SOFLAGS) -o $@ $(OBJDIR)/quicsock_server_bin.o -lquicsock -levent

$(QUICSOCK_CLIENT): $(OBJDIR)/quicsock_client_bin.o $(LIBQUICSOCK)
		$(CC) $(CCFLAGS) $(SOFLAGS) -o $@ $(OBJDIR)/quicsock_client_bin.o -lquicsock -levent

$(OBJDIR)/%.o: %.cc
		mkdir -p $(shell dirname $@)
		$(CXX) $< $(CXXFLAGS) -c -o $@ $(LIBS)

$(OBJDIR)/%.o: %.c
		mkdir -p $(shell dirname $@)
		$(CC) $< $(CCFLAGS) -c -o $@

$(LIBQUIC): $(LIBQUIC_SRCS)
		mkdir -p lib/libquic/build
		cd lib/libquic/build && cmake $(LIBQUIC_CMAKE_FLAGS) .. && make
