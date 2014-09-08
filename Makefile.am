SUBDIRS = src agent man

# .gz because github doesn't support .xz yet :-(

TAG		?= $(shell git log --pretty="format:%H" -n 1)
distdir		 = $(PACKAGE)-$(TAG)
TARFILE		 = $(distdir).tar.gz
DIST_ARCHIVES	 = $(TARFILE)

RPM_ROOT	= $(shell pwd)
RPM_OPTS	= --define "_sourcedir $(RPM_ROOT)" 	\
		  --define "_specdir   $(RPM_ROOT)" 	\
		  --define "_srcrpmdir $(RPM_ROOT)"

export:
	rm -f $(PACKAGE)-HEAD.tar.*
	if [ -f $(TARFILE) ]; then						\
	    echo `date`: Using existing tarball: $(TARFILE);			\
	else									\
	    rm -f $(PACKAGE).tar.*;						\
	    git archive --prefix=$(distdir)/ $(TAG) | gzip > $(TARFILE);	\
	    echo `date`: Rebuilt $(TARFILE);					\
	fi

srpm:	export
	rm -f *.src.rpm
	rpmbuild $(RPM_OPTS) -bs $(PACKAGE).spec

rpm:	export srpm
	rpmbuild $(RPM_OPTS) --rebuild $(RPM_ROOT)/*.src.rpm
