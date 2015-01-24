.PHONY: all clean

all: biba
biba: biba.c -lm -lssl
clean:
	rm -f *.o *.a $(PROGRAMS)
