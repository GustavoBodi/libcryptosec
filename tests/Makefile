############# CC FLAGS ###############################
NAME = test.out
CC = g++
CPPFLAGS = -std=c++14 -g -w -DGTEST_HAS_PTHREAD=0
DEFS =

############# ENVIRONMENT ###############################
INSTALL_PREFIX		?= /usr/local
OPENSSL_PREFIX ?= /usr/local/ssl
OPENSSL_LIBDIR ?= $(OPENSSL_PREFIX)/lib64
OPENSSL_INCLUDEDIR ?= $(OPENSSL_PREFIX)/include
LIBCRYPTOSEC ?= $(INSTALL_PREFIX)/lib64/libcryptosec.so
LIBCRYPTOSEC_INCLUDEDIR ?= $(INSTALL_PREFIX)/include/libcryptosec
GTEST_INCLUDEDIR ?= /usr/include
SRC_DIR ?= src/unit


############ DEPENDENCIES ############################

LIBS = $(LIBCRYPTOSEC) -L$(OPENSSL_LIBDIR) -Wl,-rpath,$(OPENSSL_LIBDIR) -lcrypto -lgtest -pthread
INCLUDES = -I$(OPENSSL_INCLUDEDIR) -I$(GTEST_INCLUDEDIR) -I$(LIBCRYPTOSEC_INCLUDEDIR)

########### OBJECTS ##################################
TEST_SRCS += $(wildcard $(SRC_DIR)/*.cpp)
OBJS += $(TEST_SRCS:.cpp=.o)

########### AUX TARGETS ##############################
.set_static:
	$(eval LIBS= $(LIBCRYPTOSEC) -lgtest -pthread)

.set_engine:
	$(eval DEFS+= -DENGINE_COMP)

.check_compiled:
	@test -s $(LIBCRYPTOSEC) || { echo "You should COMPILE libcryptosec first!"; exit 1; }

%.o: %.cpp
	$(CC) $(CPPFLAGS) $(DEFS) $(INCLUDES) -O0 -Wall -c -o "$@" "$<"

.comp: $(OBJS)
	$(CC) $(CPPFLAGS) $(DEFS) -o $(NAME) $(OBJS) $(LIBS)
	@echo 'Build complete!'

.run:
	./$(NAME)
	@echo 'Done!'

.run_engine:
	./$(NAME) --gtest_filter='EngineDeathTest.*:EngineTest.*'
	@echo 'Done!'

########### TARGETS ##################################

all: .comp

test: test_dynamic

test_dynamic: .check_compiled .comp .run

test_static: .check_compiled .set_static .comp .run

test_engine_dynamic: .check_compiled .set_engine .comp .run_engine

test_engine_static: .check_compiled .set_engine .set_static .comp .run_engine

clean:
	rm -rf ./$(SRC_DIR)/*.o $(NAME)


