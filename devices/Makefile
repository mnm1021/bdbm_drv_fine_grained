.PHONY: all bluedbm ramdrive ramdrive_timing libdummy libramdrive ocssd
all: all bluedbm ramdrive ramdrive_timing libdummy libramdrive ocssd

bluedbm:
	cd bluedbm; $(MAKE) clean; $(MAKE)

ramdrive:
	cd ramdrive; $(MAKE) clean; $(MAKE)

ramdrive_timing:
	cd ramdrive_timing; $(MAKE) clean; $(MAKE)

libdummy:
	cd libdummy; $(MAKE) clean; $(MAKE)

libramdrive:
	cd libramdrive; $(MAKE) clean; $(MAKE)

ocssd:
	cd ocssd; $(MAKE) clean; $(MAKE)

.PHONY: clean 
clean: 
	@cd bluedbm; $(MAKE) clean
	@cd ramdrive; $(MAKE) clean
	@cd ramdrive_timing; $(MAKE) clean
	@cd libdummy; $(MAKE) clean
	@cd libramdrive; $(MAKE) clean
	@cd ocssd; $(MAKE) clean
