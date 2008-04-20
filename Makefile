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

run:dohnaj1
	./dohnaj1 ftp.dump 85.71.135.84 21 192.168.72.151 57073
