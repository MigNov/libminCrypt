#!/bin/bash

./test-binary.sh				|| exit 1
./test-asymmetric.sh				|| exit 1

echo "All tests passed successfully"
exit 0
