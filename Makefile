.PHONY: docs build check sanitized-check format

build:
	catalyst build

check:
	catalyst test -r

sanitized-check:
	catalyst build -p test sanitized-debug
	build/common-test-sanitized-debug/peerfs

format:
	clang-format-22 -i include/peerfs/*.hpp src/core/*.cpp test/*.cpp

docs: main.tex
	pdflatex main.tex
	- rm -f main.aux main.log main.out main.toc
