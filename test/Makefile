#
# $Id: Makefile 888 2010-01-01 16:46:05Z doug $
# 

.SUFFIXES:
.SUFFIXES: .c .cc .cpp .o

LD=		g++

CFLAGS=		-O2 -g 
CXXFLAGS=	$(CFLAGS)
#INCPATH=	-I/opt/local/include -I/usr/local/include -I./GMP_bignum
INCPATH=	-I/opt/local/include -I/usr/local/include -I./Polarssl_bignum

LDFLAGS=
LIBPATH=	-L/opt/local/lib -L/usr/local/lib 
LIBS=	  -lgmp -lm

EXE=		a.out
OBJS=		main.o LWE.o poly.o bignum.o sha256.o

.PHONY: all

all: $(EXE)

$(EXE): $(OBJS)
	$(LD) $(LDFLAGS) $(LIBPATH) -o  $@ $^ $(LIBS)  

bignum.o: ./Polarssl_bignum/bignum.c
	$(CC) -c $(CFLAGS) $(INCPATH) $<

#bignum.o: ./GMP_bignum/bignum.c
#	$(CC) -c $(CFLAGS) $(INCPATH) $<

%.o: %.c
	$(CC) -c $(CFLAGS) $(INCPATH) $<

%.o: %.cc
	$(CXX) -c $(CXXFLAGS) $(INCPATH)   $<

%.o: %.cpp
	$(CXX) -c $(CXXFLAGS) $(INCPATH) $<



.PHONY: clean
clean:
	rm -f *core* $(EXE) *.o
