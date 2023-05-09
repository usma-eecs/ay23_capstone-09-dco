/archive -> Old version of files used during development


/DetectionScript -> current version of detection script. Detects both windows and linux machines, places results of script in "OS.log"
in zeek. This script should be placed in the "/opt/so/saltstack/local/salt/zeek/policy/custom" directory. Place the script in it's own directory,
call it whatever you want, and place the script in there and rename it "__load__.zeek"


/pcapFiles -> Pcap files used during development to derive the methods used in the script. Can be used to help test scripts.

/securityOnionQueryTests -> 

/testCases -> filed used to help test functionality of script

/Alerts -> attempted scripts to implement alerts for kali into secuirty Onion. Currently not complete and configured.


/SaltConfig -> there are all the files that must be configured for the detection script to work


KEY DIRECTORIES TO FOCUS ON FOR IMPLEMENTATION OF THIS SCRIPT IN YOUR OWN SYSTEM: /DetectionScript & /SaltConfig
FOLLOW DOCUMENTATION IN EACH DIRECTORY TO PROPERLY IMPLEMENT.
/DetectionScript should be placed first, then the /SaltConfig files
