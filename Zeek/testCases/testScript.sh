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
addTest 2 "on Linux"
addTest 3 "using HTTP"
addTest 4 "for Chromium Browsers"
num=5
addTest $num "Manual String"
expectedString="Linux x86_64 Chromium 107.0.0.0"
result="Linux x86_64 Chromium 107.0.0.0"
# CITE: https://stackoverflow.com/questions/19733437/getting-command-not-found-error-while-comparing-two-strings-in-bash
if [[ $expectedString == $result ]]; then
	testPassed $num "Chromium Linux"
else
	testFailed $num "Chromium Linux"
fi
num=5
addTest $num "Chromium Linux"
expectedString="Linux x86_64 Chromium 107.0.0.0"
result="$(zeek -C -r ../../httpWebsiteLinux.pcap -B all frameworks/software/httpOSDetect.zeek)"
if [[ $expectedString == $result ]]; then
	testPassed $num "Chromium Linux"
else
	testFailed $num "Chromium Linux"
fi

addTest $num "create OS log"

rm OS.log
if [[ ! -f "OS.log" ]]; then
        testPassed $num "create OS log no log"
else
        testFailed $num "create OS log no log"
fi

output="$(zeek -C -r ../../httpWebsiteLinux.pcap -B all frameworks/software/httpOSDetect.zeek)"
if [[ -f "OS.log" ]]; then
        testPassed $num "create OS log"
else
        testFailed $num "create OS log"
fi

addTest $num "OS log content"
output="$(zeek -C -r ../../httpWebsiteLinux.pcap -B all frameworks/software/httpOSDetect.zeek)"
expected="$(cat OSExample.log)"
result="$(cat OS.log)"
if [[ $expectedString == $result ]]; then
	testPassed $num "OS log content"
else
	testFailed $num "OS log content"
fi

addTest 4 "for FireFox Browser"
num=5
addTest $num "Manual String"
expectedString="Ubuntu Linux x86_64 Firefox 108.0"
result="Ubuntu Linux x86_64 Firefox 108.0"
if [[ $expectedString == $result ]]; then
	testPassed $num "Firefox Linux"
else
	testFailed $num "Firefox Linux"
fi

addTest 5 "Firefox Linux"
epectedString="Ubuntu Linux x86_64 Firefox 108.0"
result="$(zeek -C -r ../../httpWebsiteLinuxFirefox.pcap -B all frameworks/software/httpOSDetect.zeek | head -n 1)"
if [[ $expectedString == $result ]]; then
	testPassed $num "Firefox Linux"
else
	testFailed $num "Firefox Linux"
fi

addTest 2 "On Windows"
addTest 3 "for Internet Explore"
num=4
addTest $num "Manual String Windows 10"
expectedString="IP: 10.10.2.29 - Windows 10.0"
result="IP: 10.10.2.29 - Windows 10.0"

if [[ $expectedString == $result ]]; then
	testPassed $num "Windows 10"
else
	testFailed $num "Windows 10"
fi

addTest $num "Windows 10"
expectedString=$'IP: 10.10.2.29 - Windows 10.0\nIP: 10.10.2.29 - Windows 10.0'
result="$(zeek -C -r ../../http1.1.pcap -B all frameworks/software/windows-version-detection.zeek)"

if [[ $expectedString == $result ]]; then
	testPassed $num "Windows 10"
else
	testFailed $num "Windows 10"
fi
