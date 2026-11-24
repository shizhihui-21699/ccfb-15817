.PHONY: build verify demo clean

build:
	swift build

verify:
	swift run efbverify

demo:
	swift run efbdemo

clean:
	rm -rf .build
