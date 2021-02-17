CXX		  := g++
CXX_FLAGS := -Wall -Wextra -std=c++17 -ggdb

BIN		:= bin
SRC		:= $(shell find $(SOURCEDIR) -name '*.cpp')
INCLUDE	:= include
LIB		:= lib

LIBRARIES	:= -lXKCP -lntl -pthread -lgmp -lhelib -lcryptopp
EXECUTABLE	:= main

all: $(BIN)/$(EXECUTABLE)

run: clean all
	clear
	./$(BIN)/$(EXECUTABLE)

$(BIN)/$(EXECUTABLE): $(SRC)
	export LD_LIBRARY_PATH=./$(LIB)
	$(CXX) $(CXX_FLAGS) -I$(INCLUDE) -L$(LIB) $^ -o $@ $(LIBRARIES)

clean:
	-rm $(BIN)/*
