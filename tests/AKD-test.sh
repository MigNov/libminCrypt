#!/bin/bash

print_error()
{
	echo "$@" 1>&2
}

akd_test()
{
	local len="$1"
	local sname="$2"

	file="testtmpfile"

	rm -f test-key*

	tmStart=$(date +%s)
	../src/mincrypt -a s:1:test-key:$len > /dev/null
	../src/mincrypt -a r:1:test-key:$len > /dev/null
	../src/mincrypt -a s:2:test-key:$len > /dev/null

	# As we are emulating to be both sender and receiver (or both Alice and Bob, if you prefer :-))
	# we have to rename the file to different names. File test-key is a private key and the file
	# test-key.pub is the public key for corresponding to it
	mv test-key test-keyW1
	mv test-key.pub test-keyW1.pub

	../src/mincrypt -a r:2:test-key:$len > /dev/null

	mv test-key test-keyW2
	mv test-key.pub test-keyW2.pub

	# We need to generate another key pair - not compatible
	cp test-key.common test-keyNW.common

	../src/mincrypt -a r:1:test-keyNW:$len > /dev/null
	../src/mincrypt -a r:2:test-keyNW:$len > /dev/null

	res="PASS"
	snamex=${sname// /_}
	sfile="$file-$snamex"
	../src/mincrypt -a s:3:test-keyW1:$len --input-file $TEMP_DIR/$file --output-file=$TEMP_DIR/$sfile.enc > /dev/null
	../src/mincrypt -a r:3:test-keyW2:$len --input-file $TEMP_DIR/$sfile.enc --output-file=$TEMP_DIR/$sfile.dec --decrypt > /dev/null
	../src/mincrypt -a r:3:test-keyNW:$len --input-file $TEMP_DIR/$sfile.enc --output-file=$TEMP_DIR/$sfile.idec --decrypt > /dev/null 2> /dev/null

	diff $TEMP_DIR/$file $TEMP_DIR/$sfile.dec > /dev/null
	if [ $? -ne 0 ]; then
		res="FAIL"
	else
		diff $TEMP_DIR/$file $TEMP_DIR/$sfile.idec > /dev/null 2> /dev/null
		if [ $? -eq 0 ]; then
			res="FAIL"
		fi
	fi

	tmEnd=$(date +%s)

	let tm=$tmEnd-$tmStart

	rm -f test-key*
	echo "Test for length of $sname: [$res] (time $tm seconds)"

	if [ "$res" == "FAIL" ]; then
		return 1
	fi
}
tmStart1="$(date +%s)"

do_check()
{
	local cmd="$1"
	local sname="$2"

	if ! $cmd "$sname"; then
		print_error "Test '$cmd' failed"
		exit 1
	fi

	let testNr=$testNr+1
}

test_prepare()
{
	local size="$1"

	dd if=/dev/urandom of=$TEMP_DIR/testtmpfile bs=1M count=$size > /dev/null 2> /dev/null
}

test_finish()
{
	rm -rf $TEMP_DIR
}

memfree="$(cat /proc/meminfo | grep MemFree: | awk '{split($0, a, ":"); split(a[2], b, "kB"); gsub(/[[:space:]]/, "", b[1]); print b[1] }')"
testNr=0
loadtest=0
if [ "$1" == "loadtest" ]; then
	loadtest=1
fi

TEMP_DIR="$(mktemp -d)"
echo "Using temporary directory: $TEMP_DIR"

test_prepare 50

do_check "akd_test 16" "16 B"
do_check "akd_test 512" "512 B"
do_check "akd_test 1024" "1 kiB"
do_check "akd_test 2048" "2 kiB"
do_check "akd_test 4096" "4 kiB"
do_check "akd_test 8192" "8 kiB"

tmEnd1="$(date +%s)"
let tm1=$tmEnd1-$tmStart1

echo "Cleaning up directory: $TEMP_DIR"
test_finish

echo "All tests ($testNr test(s)) passed in $tm1 second(s)"
