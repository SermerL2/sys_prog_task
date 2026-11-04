CXX ?= g++
CXXFLAGS ?= -std=c++17 -O2 -Wall -Wextra
runtime: runtime.cpp
	$(CXX) $(CXXFLAGS) $< -lutil -o $@
test: runtime
	python3 tests.py
clean:
	rm -f runtime
.PHONY: test clean
