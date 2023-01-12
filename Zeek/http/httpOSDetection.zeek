##! Windows systems access a Microsoft Certificate Revocation List (CRL) periodically. The
##! user agent for these requests reveals which version of Crypt32.dll installed on the system,
##! which can uniquely identify the version of Windows that's running.
##!
##! This script will log the version of Windows that was identified to the Software framework.

@load base/protocols/http
@load base/frameworks/software
module OS;
export {
        redef enum Software::Type += {
                ## Identifier for Windows operating system versions
                WINDOWS,
        };

        type Software::name_and_version: record {
                name   : string;
                version: Software::Version;
        };

	global arr1: string_vec;
	global arr2: string_vec;
	global arr3: string_vec;
	global versionArr: string_vec;
}

event HTTP::log_http(rec: HTTP::Info) &priority=5
        {
        # if ( rec?$host && rec?$user_agent && /crl.microsoft.com/ in rec$host &&
            #  /Microsoft-CryptoAPI\// in rec$user_agent ) 
       print rec$user_agent;
	if (rec?$host && rec?$user_agent && /Linux/ in rec$user_agent) {
		arr1 = split_string1(rec$user_agent, /Linux/);
		print arr1[0];
		print /\n/;
		print arr1[1];
		}
	 }
