#!/bin/bash
# Cite: https://linuxhandbook.com/change-echo-output-color/
# Cite: https://www.geeksforgeeks.org/bash-script-define-bash-variables-and-its-types/
# Cite: https://www.geeksforgeeks.org/bash-scripting-if-statement/
RED='\033[0;31m'
GREEN='\033[0;32m'
NOCOLOR='\033[0m'

testPassed () {
        local OUTPUT=""
        for ((i = 0; i < $1; i++)); do OUTPUT+="\t"; done
        echo -e "$OUTPUT${GREEN}$2 - Test Passed!${NOCOLOR}"
}
testFailed () {
        local OUTPUT=""
        for ((i = 0; i < $1; i++)); do OUTPUT+="\t"; done
        echo -e "$OUTPUT${RED}$2 - Test Failed!${NOCOLOR}"      
}

addTest () {
        local OUTPUT=""
        for ((i = 0; i < $1; i++)); do OUTPUT+="\t"; done
        echo -e "$OUTPUT$2"
}

addTest 0 "Zeek Scripts"
addTest 1 "can OS fingerprint"
addTest 2 "using HTTP"
addTest 3 "on Linux"
addTest 4 "for Chromium Browsers"
addTest 5 "blank string"
expectedString=""
result=""
if [$expectedString == $result]; then
        testPassed 5 "blank string"
else
        testFailed 5 "blank string"
fi
