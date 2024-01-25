############# CC FLAGS ###############################
NAME		?= libcryptosec.so
CC			:= g++
CPPFLAGS	?= -std=c++98 -fPIC --coverage -Wno-deprecated-declarations 

############# ENVIRONMENT ###############################
OPENSSL_PREFIX		?= /usr
OPENSSL_LIBDIR		?= $(OPENSSL_PREFIX)/lib64
OPENSSL_INCLUDEDIR	?= $(OPENSSL_PREFIX)/include
LIBP11_PREFIX		?= /usr
LIBP11_LIBDIR		?= $(LIBP11_PREFIX)/lib64
LIBP11_INCLUDEDIR	?= $(LIBP11_PREFIX)/include
INSTALL_PREFIX		?= /usr/local
INSTALL_LIBDIR		?= $(INSTALL_PREFIX)/lib64
INSTALL_INCLUDEDIR	?= $(INSTALL_PREFIX)/include

############ DEPENDENCIES ############################

STATIC_LIBS	:= $(OPENSSL_LIBDIR)/libcrypto.a $(OPENSSL_LIBDIR)/libssl.a $(LIBP11_LIBDIR)/libp11.a -ldl
LIBS		:= -L$(OPENSSL_LIBDIR) -L$(LIBP11_LIBDIR) -Wl,-rpath,$(OPENSSL_LIBDIR):$(LIBP11_LIBDIR) -lp11 -lcrypto -Wstack-protector
INCLUDES	:= -I./include -I$(OPENSSL_INCLUDEDIR) -I$(LIBP11_INCLUDEDIR)

########### OBJECTS ##################################
BUILD_ROOT	?= build
CPP_SRCS	:= $(shell find src -name "*.cpp")
OBJS 		:= $(CPP_SRCS:%.cpp=$(BUILD_ROOT)/%.o)

########### TARGETS ##################################

.PHONY: all release static static_release clean install uninstall

all: $(OBJS)
	$(CC) $(CPPFLAGS) -shared -o $(NAME) $(OBJS) $(LIBS)
	@echo 'Build complete!'

release: all
	strip $(NAME)

static: $(OBJS)
	$(CC) $(CPPFLAGS) -shared -o $(NAME) $(OBJS) $(STATIC_LIBS)
	@echo 'Build complete!'

static_release: static
	strip $(NAME)

$(OBJS): $(BUILD_ROOT)/%.o: %.cpp
	@echo 'Building file: $<'
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(INCLUDES) -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o"$@" "$<"
	@echo ' '

clean:
	rm -rf $(NAME) $(BUILD_ROOT)

install: $(NAME)
	@echo 'Installing libcryptosec ...'
	@mkdir -p $(INSTALL_LIBDIR)
	@cp $(NAME) $(INSTALL_LIBDIR)
	@mkdir -m 0755 -p $(INSTALL_INCLUDEDIR)/libcryptosec
	@mkdir -m 0755 -p $(INSTALL_INCLUDEDIR)/libcryptosec/exception
	@mkdir -m 0755 -p $(INSTALL_INCLUDEDIR)/libcryptosec/certificate
	@mkdir -m 0755 -p $(INSTALL_INCLUDEDIR)/libcryptosec/ec
	@cp -f include/libcryptosec/*.h $(INSTALL_INCLUDEDIR)/libcryptosec/
	@cp -f include/libcryptosec/exception/* $(INSTALL_INCLUDEDIR)/libcryptosec/exception
	@cp -f include/libcryptosec/certificate/* $(INSTALL_INCLUDEDIR)/libcryptosec/certificate
	@cp -f include/libcryptosec/ec/* $(INSTALL_INCLUDEDIR)/libcryptosec/ec
	@echo 'Instalation complete!'

uninstall:
	@echo 'Uninstalling libcryptosec ...'
	@rm -rf $(INSTALL_LIBDIR)/$(NAME)
	@rm -rf $(INSTALL_INCLUDEDIR)/libcryptosec
	@echo 'Uninstalation complete!'
