#!/bin/bash

print_error()
{
	echo "$@" 1>&2
}

dh_test()
{
	local len="$1"
	local sname="$2"

	file="testtmpfile"

	rm -f test-key*

	tmStart=$(date +%s)
	../src/mincrypt -h s:1:test-key:$len > /dev/null
	../src/mincrypt -h r:1:test-key:$len > /dev/null
	../src/mincrypt -h s:2:test-key:$len > /dev/null

	# As we are emulating to be both sender and receiver (or both Alice and Bob, if you prefer :-))
	# we have to rename the file to different names. File test-key is a private key and the file
	# test-key.pub is the public key for corresponding to it
	mv test-key test-key2
	mv test-key.pub test-key2.pub

	../src/mincrypt -h r:2:test-key:$len > /dev/null

	res="PASS"
	# Better test is to put input and output files to do real encryption
	# Also, the lines below work only when debug log is enabled which is not optimal
	#../src/mincrypt -h s:3:test-key:$len > tmpA
	#../src/mincrypt -h r:3:test-key2:$len > tmpB
	#if ! diff -up tmpA tmpB; then
	#	res="FAIL"
	#fi
	#rm -f tmpA tmpB

	snamex=${sname// /_}
	sfile="$file-$snamex"
	../src/mincrypt -h s:3:test-key:$len --input-file $TEMP_DIR/$file --output-file=$TEMP_DIR/$sfile.enc > /dev/null
	../src/mincrypt -h r:3:test-key2:$len --input-file $TEMP_DIR/$sfile.enc --output-file=$TEMP_DIR/$sfile.dec --decrypt > /dev/null

	diff $TEMP_DIR/$file $TEMP_DIR/$sfile.dec > /dev/null
	if [ $? -ne 0 ]; then
		res="FAIL"
	fi

	tmEnd=$(date +%s)

	let tm=$tmEnd-$tmStart

	rm -f test-key*
	echo "Test for length of $sname: [$res] (time $tm seconds)"

	if [ "$res" == "FAIL" ]; then
		return 1
	fi
}
tmStart="$(date +%s)"

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

test_prepare 10

memfree="$(cat /proc/meminfo | grep MemFree: | awk '{split($0, a, ":"); split(a[2], b, "kB"); gsub(/[[:space:]]/, "", b[1]); print b[1] }')"
testNr=0
loadtest=0
if [ "$1" == "loadtest" ]; then
	loadtest=1
fi

TEMP_DIR="$(mktemp -d)"
echo "Using temporary directory: $TEMP_DIR"

test_prepare 10

do_check "dh_test 16" "16 B"
do_check "dh_test 512" "512 B"
do_check "dh_test 1024" "1 kiB"
do_check "dh_test 2048" "2 kiB"
do_check "dh_test 4096" "4 kiB"
do_check "dh_test 8192" "8 kiB"
do_check "dh_test 16384" "16 kiB"
do_check "dh_test 32768" "32 kiB"

# 262144 kB is 256 Megs as we need to have something free for the system not to run into OOM
if [ $memfree -gt 262144 -a "$loadtest" == "1" ]; then
	do_check "dh_test 65536" "64 kiB"
	do_check "dh_test 131072" "128 kiB"
	do_check "dh_test 262144" "256 kiB"
	do_check "dh_test 524288" "512 kiB"
fi

tmEnd="$(date +%s)"
let tm=$tmEnd-$tmStart

echo "Cleaning up directory: $TEMP_DIR"
test_finish

echo "All tests ($testNr test(s)) passed in $tm second(s)"
