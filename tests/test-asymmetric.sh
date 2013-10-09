#!/bin/bash

SIZEMB=2
SALT1="test"
SALT2="tesu"
PASSWORD1="password"
PASSWORD2="passwore"
KEYSIZE=1024
KEYFILE_PREFIX_1="test-key1"
KEYFILE_PREFIX_2="test-key2"
KEYFILE_PREFIX_1X="test-key1x"
SKIP_KEYGEN=0

bail()
{
	local msg="$1"
	echo "ERROR: $msg !"
	exit 1
}

if [ -z "$1" ]; then
	fn="$(mktemp)"
	dd if=/dev/urandom of=$fn bs=1M count=$SIZEMB
	new=1
else
	fn="$1"
	new=0
fi

../src/mincrypt --input-file=$fn --output-file=$fn.enc --salt=$SALT1 --password=$PASSWORD1
../src/mincrypt --input-file=$fn.enc --output-file=$fn.dec --salt=$SALT1 --password=$PASSWORD1 --decrypt
if [ "x$?" != "x0" ]; then
	bail "Test for decryption with valid salt and valid password failed"
fi

diff -up $fn $fn.dec >/dev/null
if [ "x$?" != "x0" ]; then
	bail "Check for decryption with valid salt and valid password failed"
fi

../src/mincrypt --input-file=$fn.enc --output-file=$fn.dec --salt=$SALT1 --password=$PASSWORD2 --decrypt
if [ "x$?" == "x0" ]; then
	bail "Test for decryption with valid salt and invalid password failed"
fi

../src/mincrypt --input-file=$fn.enc --output-file=$fn.dec --salt=$SALT2 --password=$PASSWORD1 --decrypt
if [ "x$?" == "x0" ]; then
	bail "Test for decryption with invalid salt and valid password failed"
fi

../src/mincrypt --input-file=$fn.enc --output-file=$fn.dec --salt=$SALT2 --password=$PASSWORD2 --decrypt
if [ "x$?" == "x0" ]; then
	bail "Test for decryption with invalid salt and invalid password failed"
fi

echo "All symmetric algorithm tests passed"

if [ "x$SKIP_KEYGEN" != "x1" ]; then
	../src/mincrypt --key-size $KEYSIZE --salt $SALT1 --password $PASSWORD1 --key-file $KEYFILE_PREFIX_1
	../src/mincrypt --key-size $KEYSIZE --salt $SALT1 --password $PASSWORD2 --key-file $KEYFILE_PREFIX_2
	../src/mincrypt --key-size $KEYSIZE --salt $SALT1 --password $PASSWORD1 --key-file $KEYFILE_PREFIX_1X
	echo "All 3 keys generated"
else
	echo "Key generation has been skipped"
fi

../src/mincrypt --input-file=$fn --output-file=$fn.enc --salt=$SALT1 --password=$PASSWORD1 --key-file=$KEYFILE_PREFIX_1.pub
../src/mincrypt --input-file=$fn.enc --output-file=$fn.dec --salt=$SALT1 --password=$PASSWORD1 --decrypt --key-file=$KEYFILE_PREFIX_1.key
if [ "x$?" != "x0" ]; then
	bail "Test for decryption with valid salt, valid password and valid key failed"
fi

diff -up $fn $fn.dec >/dev/null
if [ "x$?" != "x0" ]; then
	bail "Check for decryption with valid salt and valid password failed"
fi

../src/mincrypt --input-file=$fn.enc --output-file=$fn.dec --salt=$SALT2 --password=$PASSWORD1 --decrypt --key-file=$KEYFILE_PREFIX_1.key
if [ "x$?" == "x0" ]; then
	bail "Test for decryption with invalid salt, valid password and valid key failed"
fi

../src/mincrypt --input-file=$fn.enc --output-file=$fn.dec --salt=$SALT1 --password=$PASSWORD2 --decrypt --key-file=$KEYFILE_PREFIX_1.key
if [ "x$?" == "x0" ]; then
	bail "Test for decryption with valid salt, invalid password and valid key failed"
fi

../src/mincrypt --input-file=$fn.enc --output-file=$fn.dec --salt=$SALT2 --password=$PASSWORD2 --decrypt --key-file=$KEYFILE_PREFIX_1.key
if [ "x$?" == "x0" ]; then
	bail "Test for decryption with invalid salt, invalid password and valid key failed"
fi

../src/mincrypt --input-file=$fn.enc --output-file=$fn.dec --salt=$SALT1 --password=$PASSWORD1 --decrypt --key-file=$KEYFILE_PREFIX_1X.key
if [ "x$?" == "x0" ]; then
	bail "Test for decryption with valid salt, valid password and invalid key failed"
fi

../src/mincrypt --input-file=$fn.enc --output-file=$fn.dec --salt=$SALT1 --password=$PASSWORD2 --decrypt --key-file=$KEYFILE_PREFIX_1X.key
if [ "x$?" == "x0" ]; then
	bail "Test for decryption with valid salt, invalid password and invalid key failed"
fi

../src/mincrypt --input-file=$fn.enc --output-file=$fn.dec --salt=$SALT2 --password=$PASSWORD2 --decrypt --key-file=$KEYFILE_PREFIX_1X.key
if [ "x$?" == "x0" ]; then
	bail "Test for decryption with invalid salt, invalid password and invalid key failed"
fi

../src/mincrypt --input-file=$fn.enc --output-file=$fn.dec --salt=$SALT1 --password=$PASSWORD1 --decrypt --key-file=$KEYFILE_PREFIX_2.key
if [ "x$?" == "x0" ]; then
	bail "Test for decryption with valid salt, valid password and invalid key failed"
fi

echo "All asymmetric tests passed successfully"
rm -f $KEYFILE_PREFIX_1.pub $KEYFILE_PREFIX_2.pub $KEYFILE_PREFIX_1X.pub $KEYFILE_PREFIX_1.key $KEYFILE_PREFIX_2.key $KEYFILE_PREFIX_1X.key $fn.enc $fn.dec

if [ $new -eq 1 ]; then
	rm -f $fn
fi

exit 0
