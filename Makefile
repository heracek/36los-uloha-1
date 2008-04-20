# all after symbol '#' is comment

# === which communication library to use ===
CC	=	gcc
CFLAGS	=      
LIBS	=	-lpcap

default:	dohnaj1

dohnaj1:dohnaj1.c
	$(CC) $(CFLAGS) -o dohnaj1 dohnaj1.c $(LIBS)

clear:
	\rm dohnaj1 

