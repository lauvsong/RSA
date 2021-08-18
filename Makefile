rsa: rsa.c
	gcc rsa.c -L.. -lcrypto  -I../include/crypto -o rsa

clean:
	rm rsa