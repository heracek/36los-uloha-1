# all after symbol '#' is comment

# === which communication library to use ===
CC	=	g++
CFLAGS	=      
LIBS	=	-lpcap

default:	main

main:main.cpp
	$(CC) $(CFLAGS) -o main main.cpp $(LIBS)

clear:
	\rm main out.data out.info

run:main
	./main ftp.dump 85.71.135.84 21 192.168.72.151 57073
