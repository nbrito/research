# Neptune Makefile
# daemon9, 1996 Guild Productions

all:
	@gcc -o neptune neptune.c
	@echo ""
	@echo "'make install' will install the program..."
	@echo ""
	@echo "Warning!  Neptune is installed SUID root by default!"
	@echo ""
	@echo "route@infonexus.com / Guild Corporation"
install:
	strip ./neptune
	mv ./neptune /usr/local/bin/neptune
	chmod 4755 /usr/local/bin/neptune
	@echo "root" > /etc/sfaccess.conf
	@echo "Installation complete, access list is /etc/sfaccess.conf"
clean: 
	@rm -f *.o neptune /etc/sfaccess.conf
