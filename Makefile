.PHONY: docs build check live-check sanitized-check format

build:
	catalyst build
	catalyst build -p cli

check:
	catalyst test -r
	catalyst build -p cli
	python3 test/cli_test.py
	$(MAKE) live-check

live-check:
	catalyst build -p cli
	catalyst build -p cli integration
	python3 test/live_test.py

sanitized-check:
	catalyst build -p test sanitized-debug
	build/common-test-sanitized-debug/peerfs
	catalyst build -p cli sanitized-debug
	python3 test/cli_test.py build/common-cli-sanitized-debug/peerfs
	catalyst build -p cli integration sanitized-debug
	python3 test/live_test.py build/common-cli-integration-sanitized-debug/peerfs

format:
	clang-format-22 -i include/peerfs/*.hpp src/core/*.cpp src/cli/*.cpp src/live/*.cpp src/live/*.hpp test/*.cpp

docs: main.tex
	pdflatex main.tex
	- rm -f main.aux main.log main.out main.toc
