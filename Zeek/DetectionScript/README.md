Current version of detection script. Detects both windows and linux machines, places results of script in "OS.log"
in zeek. This script should be placed in the ```/opt/so/saltstack/local/salt/zeek/policy/custom``` directory. Place the script in it's own directory,
call it whatever you want, and place the script in there and rename it ```__load__.zeek```

# Methods:
### Windows Crypto API Captures:
Passively fingerprinting Windows OS—up to Windows 10— by capturing HTTP packets using the Windows Crypto API.
Linux User-agent String: Passively fingerprinting using user-agent string for browser requests.

### Linux Update Captures:
Passively fingerprinting by capturing Linux Updates through HTTP packets.  We can distinguish between Linux OS types. 
Overall Capabilities: Fingerprint operating systems and specific Linux versions in a passive way.
