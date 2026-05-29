CC = gcc
CFLAGS = -Wall -Wextra -O2
LDLIBS = -lssl -lcrypto

TARGETS = client proxy server

all: $(TARGETS)

client: client.c
	$(CC) $(CFLAGS) -o $@ $< $(LDLIBS)

proxy: proxy.c
	$(CC) $(CFLAGS) -o $@ $< $(LDLIBS)

server: server.c
	$(CC) $(CFLAGS) -o $@ $< $(LDLIBS)

clean:
	rm -f $(TARGETS)

distclean: clean
	rm -rf certs input.txt

run-server: server
	./server certs/server.crt certs/server.key 9443

run-proxy: proxy
	./proxy certs/proxy.crt certs/proxy.key certs/ca_server.pem 8443 127.0.0.1 9443

run-client-proxy: client
	./client 127.0.0.1 8443 certs/ca_bundle.pem input.txt

run-client-direct: client
	./client 127.0.0.1 9443 certs/ca_bundle.pem input.txt

.PHONY: all clean distclean run-server run-proxy run-client-proxy run-client-direct
