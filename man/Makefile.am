man_MANS	= sbd.8

EXTRA_DIST	= $(man_MANS)

sbd.8:	sbd.8.pod
	@POD2MAN@ -s 8 -c "STONITH Block Device" -r "SBD" -n "SBD" $< $@

