rm *.o
gcc `libnet-config --defines` `libnet-config --libs` -o packet.o packet.c -Wall -Wextra -lnet -c
gcc `libnet-config --defines` `libnet-config --libs` -o flood.o flood.c -Wall -Wextra -lnet -c
gcc -o sniff.o sniff.c -Wall -Wextra -lpcap -c
gcc `libnet-config --defines` `libnet-config --libs` -o main.o main.c -Wall -Wextra -lnet -lpcap -lpthread -c
gcc `libnet-config --defines` `libnet-config --libs` -o main main.o packet.o flood.o sniff.o -Wall -Wextra -lnet -lpcap -lpthread
