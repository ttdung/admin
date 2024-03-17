.PHONY: all, clean

CXXFLAGS = $(CXX11FLAGS) $(OS_CXXFLAGS) -pthread -Wall -g -O2 -DSSL_LIB_INIT -I./include  -I/usr/local/include  $(LOC_INC)
LDFLAGS = -L/home/mmt/src/Admin/lib -L/usr/local/lib $(LOC_LIB)
LIBS = -lcrypto -lrelic -lrelic_ec -lopenabe

all: du do admin register

liblibrary.so: lib_bridge.cpp
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -fPIC -shared -o liblibrary.so lib_bridge.cpp $(LIBS)

du: liblibrary.so cmd/du/du.go
	go build -o du cmd/du/du.go

do: liblibrary.so cmd/do/do.go
	go build -o do cmd/do/do.go

admin: liblibrary.so cmd/admin/admin.go
	go build -o admin cmd/admin/admin.go

register: liblibrary.so cmd/register/register.go
	go build -o register cmd/register/register.go

clean:
	rm -rf admin du do register