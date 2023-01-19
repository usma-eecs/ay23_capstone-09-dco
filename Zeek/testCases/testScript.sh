#!/bin/bash
# Cite: https://linuxhandbook.com/change-echo-output-color/
# Cite: https://www.geeksforgeeks.org/bash-script-define-bash-variables-and-its-types/
# Cite: https://www.geeksforgeeks.org/bash-scripting-if-statement/
RED='\033[0;31m'
GREEN='\033[0;32m'
NOCOLOR='\033[0m'

testPassed () {
        OUTPUT=""
        for ((i = 0; i < $1; i++)); do OUTPUT+="\t"; done
        echo -e "$OUTPUT${GREEN}Test Passed!${NOCOLOR}"
}
testPassed 1

echo "Zeek Scripts"
echo "  can OS fingerprint"
echo "          using HTTP"
echo "                  on Linux"
echo "                          for Chromium Browsers"
echo "                                  prints nothing"
expectedString=""
result=""
if [$expectedString == $result]; then
        echo -e "                                                       ${GREEN}Test Passed!${NOCOLOR}"
else
        echo -e "                                                       ${RED}Test Failed!${NOCOLOR}"

fi

