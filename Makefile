.PHONY: all, clean

CXXFLAGS = $(CXX11FLAGS) $(OS_CXXFLAGS) -pthread -Wall -g -O2 -DSSL_LIB_INIT -I./include  -I/usr/local/include  $(LOC_INC)
LDFLAGS = -L/home/mmt/src/Admin/lib -L/usr/local/lib $(LOC_LIB)
LIBS = -lcrypto -lrelic -lrelic_ec -lopenabe

all: query enc admin register store

liblibrary.so: lib_bridge.cpp
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -fPIC -shared -o liblibrary.so lib_bridge.cpp $(LIBS)

query: liblibrary.so cmd/query/query.go
	go build -o query cmd/query/query.go

enc: liblibrary.so cmd/enc/enc.go
	go build -o enc cmd/enc/enc.go

admin: liblibrary.so cmd/admin/admin.go
	go build -o admin cmd/admin/admin.go

register: liblibrary.so cmd/register/register.go
	go build -o register cmd/register/register.go

store: liblibrary.so cmd/store/store.go
	go build -o store cmd/store/store.go

clean:
	rm -rf admin query enc register store
