.PHONY: all

CXXFLAGS = $(CXX11FLAGS) $(OS_CXXFLAGS) -pthread -Wall -g -O2 -DSSL_LIB_INIT -I./include  -I/usr/local/include  $(LOC_INC)
LDFLAGS = -L./lib -L/usr/local/lib $(LOC_LIB)
LIBS = -lcrypto -lrelic -lrelic_ec -lopenabe

all: liblibrary.so

liblibrary.so: lib_bridge.cpp
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -fPIC -shared -o liblibrary.so lib_bridge.cpp $(LIBS)

