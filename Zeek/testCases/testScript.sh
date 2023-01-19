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
addTest 5 "Manual String"
expectedString=""
result=""
# CITE: https://stackoverflow.com/questions/19733437/getting-command-not-found-error-while-comparing-two-strings-in-bash
if [[ $expectedString == $result ]]; then
        testPassed 5 "Chromium Linux"
else
        testFailed 5 "Chromium Linux"
fi
addTest 5 "Chromium Linux"
expectedString="Linux x86_64 Chromium 107.0.0.0"
result="$(zeek -C -r ../../httpWebsiteLinux.pcap -B all frameworks/software/httpOSDetect.zeek)"
if [[ $expectedString == $result ]]; then
        testPassed 5 "Chromium Linux"
else
        testFailed 5 "Chromium Linux"
fi

addTest 4 "for FireFox Browser"
addTest 5 "Manual String"
expectedString="Ubuntu Linux x86_64 Firefox 108.0"
result="Ubuntu Linux x86_64 Firefox 108.0"
if [[ $expectedString == $result ]]; then
        testPassed 5 "Firefox Linux"
else
        testFailed 5 "Firefox Linux"
fi

addTest 5 "Firefox Linux"
epectedString="Ubuntu Linux x86_64 Firefox 108.0"
result="$(zeek -C -r ../../httpWebsiteLinuxFirefox.pcap -B all frameworks/software/httpOSDetect.zeek | head -n 1)"
if [[ $expectedString == $result ]]; then
        testPassed 5 "Firefox Linux"
else
        testFailed 5 "Firefox Linux"
fi
