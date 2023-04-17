CXX=g++

all: main.cpp
	$(CXX) main.cpp -o ipk-sniffer -lpcap -Wall -Wextra