#!/bin/bash
#
# Copyright (C) 2013 Lars Marowsky-Bree <lmb@suse.com>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This software is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#

# TODO:
# - More tests
# - Handle optional, long-running tests better
# - Support for explicitly running a single test
# - Verify output from commands
#   - Normalize uuids and device names so they are diffable
#   - Log to file, instead of syslog is needed
# - How to test watch mode?
# - Can the unit/service file be tested? or at least the wrapper?

sbd_setup() {
	trap sbd_teardown EXIT
	for N in $(seq 3) ; do
		F[$N]=$(mktemp /tmp/sbd.device.$N.XXXXXX)
		dd if=/dev/zero of=${F[$N]} count=2048
		L[$N]=$(losetup -f)
		losetup ${L[$N]} ${F[$N]}
		D[$N]="/dev/mapper/sbd_$N"
		dmsetup create sbd_$N --table "0 2048 linear ${L[$N]} 0"
	done
}

sbd_teardown() {
	for N in $(seq 3) ; do
		dmsetup remove sbd_$N
		losetup -d ${L[$N]}
		rm -f ${F[$N]}
	done
}

sbd_dev_fail() {
	dmsetup wipe_table sbd_$1
}

sbd_dev_resume() {
	dmsetup suspend sbd_$1
	dmsetup load sbd_$1 --table "0 2048 linear ${L[$1]} 0"
	dmsetup resume sbd_$1
}

_ok() {
	echo -- $@
	$@
	rc=$?
	if [ $rc -ne 0 ]; then
		echo "$@ failed with $rc"
		exit
	fi
}

_no() {
	echo -- $@
	$@
	rc=$?
	if [ $rc -eq 0 ]; then
		echo "$@ did NOT fail ($rc)"
		exit
	fi
	return 0
}

test_1() {
	echo "Creating three devices"
	_ok sbd -d ${D[1]} -d ${D[2]} -d ${D[3]} create
	_ok sbd -d ${D[1]} -d ${D[2]} -d ${D[3]} dump
}

test_2() {
	echo "Basic functionality"
	for S in `seq 2` ; do
		_ok sbd -d ${D[1]} -d ${D[2]} -d ${D[3]} allocate "test-$S"
	done
	_ok sbd -d ${D[1]} -d ${D[2]} -d ${D[3]} -n test-1 message test-2 reset
	_ok sbd -d ${D[1]} -d ${D[2]} -d ${D[3]} list
}

test_3() {
	echo "Start mode (expected not to start, because reset was written in test_2)"
	_no sbd -d ${D[1]} -d ${D[2]} -d ${D[3]} -n test-2 -Z -Z -Z -S 1 watch
}

test_4() {
	echo "Deliver message with 1 failure"
	sbd_dev_fail 1
	_no sbd -d ${D[1]} -n test-1 message test-2 exit
	_no sbd -d ${D[1]} -d ${D[2]} -n test-1 message test-2 exit
	_ok sbd -d ${D[1]} -d ${D[2]} -d ${D[3]} -n test-1 message test-2 exit
	sbd_dev_resume 1

}

test_5() {
	echo "Deliver message with 2 failures"
	sbd_dev_fail 1
	sbd_dev_fail 2
	_no sbd -d ${D[1]} -d ${D[2]} -n test-1 message test-2 exit
	_no sbd -d ${D[1]} -d ${D[2]} -d ${D[3]} -n test-1 message test-2 exit
	sbd_dev_resume 1
	sbd_dev_resume 2

}

test_6() {
	echo "Deliver message with 3 failures"
	sbd_dev_fail 1
	sbd_dev_fail 2
	sbd_dev_fail 3
	_no sbd -d ${D[1]} -d ${D[2]} -d ${D[3]} -n test-1 message test-2 exit
	sbd_dev_resume 1
	sbd_dev_resume 2
	sbd_dev_resume 3
}

test_101() {
	echo "Creating one device"
	_ok sbd -d ${D[1]} create
}

test_102() {
	echo "Creating two devices"
	_ok sbd -d ${D[1]} -d ${D[2]} create
}

test_7() {
	echo "Allocate all slots plus 1"
	_ok sbd -d ${D[1]} -d ${D[2]} -d ${D[3]} -2 0 create
	for S in `seq 255` ; do
		_ok sbd -d ${D[1]} -d ${D[2]} -d ${D[3]} allocate "test-$S"
	done
	_no sbd -d ${D[1]} -d ${D[2]} -d ${D[3]} allocate "test-256"
}

test_8() {
	echo "Non-existent device path"
	_no sbd -d /dev/kfdifdifdfdlfd -create 2>/dev/null
}

test_9() {
	echo "Basic sbd invocation"
	_no sbd
	_ok sbd -h
}

sbd_setup

for T in $(seq 9); do
	if ! test_$T ; then
		echo "FAILURE: Test $T"
		break
	fi
	echo "SUCCESS: Test $T"
done

echo "SUCCESS: All tests completed"

