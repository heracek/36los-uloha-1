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

run_data:main
	./main ftp.dump 85.71.135.84 1611 192.168.72.151 57075

run_http:main
	./main http_witp_jpegs.pcap 209.225.11.237 80 10.1.1.101 3179

run_frag:main
	./main teardrop.pcap 10.1.1.1 31915 129.111.30.27 20197
