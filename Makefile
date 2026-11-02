.PHONY: all build ipa applejpeg clean

all: ipa

build:
	./build.sh

ipa: build

applejpeg:
	./PoC/applejpeg/build.sh

clean:
	rm -rf build
