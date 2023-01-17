## Attempting to model https://github.com/fatemabw/bro-scripts/blob/master/Mac-version-detection.bro

@load base/protocols/http
@load base/frameworks/software
module OS;
export {
        redef enum Software::Type += {
                ## Identifier for Windows operating system versions
                WINDOWS,
                LINUX,
        };

        redef enum Log::ID += { LOG };

        type osInfo: record {
                ip:     addr &log;
                os:     string &log;
        };

        type Software::name_and_version: record {
                name   : string;
                version: Software::Version;
        };

        global arr1: string_vec;
        global arr2: string_vec;
        global arr3: string_vec;
        global arr4: string_vec;
        global arr5: string_vec;
        global versionArr: string_vec;
}

event zeek_init() {
        Log::create_stream(LOG, [$columns=osInfo, $path="OS"]);
}

event HTTP::log_http(rec: HTTP::Info) &priority=5
        {
        # if ( rec?$host && rec?$user_agent && /crl.microsoft.com/ in rec$host &&
            #  /Microsoft-CryptoAPI\// in rec$user_agent ) 
       # print rec$user_agent;
        if (rec?$host && rec?$user_agent && /Linux/ in rec$user_agent) {
                # ensures that we are working with a chrome browser
                # a firefox browser parses differently/gives more information
                if (/Chrome\// in rec$user_agent) {
                arr1 = split_string1(rec$user_agent, /\(/);
                arr2 = split_string1(arr1[1], / /);
                arr3 = split_string(arr2[1], /\)/);
                # print arr3[0]; # Linux x86_64
                arr4 = split_string1(rec$user_agent, /Chrome\//);
                arr5 = split_string1(arr4[1], / /);
                # print arr4[1]; # Chrome version # + safari
                # print arr5[0]; # Chrome version #

                print arr3[0] + " " + "Chromium " + arr5[0];
                Log::write(OS::LOG, [
                        $ip=rec$id$orig_h,
                        $os=arr3[0] + " " + "Chromium " + arr5[0]]);
                }
                else if ("Firefox/" in rec$user_agent) {
                arr1 = split_string_n(rec$user_agent, /\; /, F, 3);
                # print arr1[0];
                # print arr1[1]; # ubuntu
                # print arr1[2]; # linux w/ archetecture type
                # print arr1[3]; # rest of string that is not used
                arr2 = split_string1(arr1[3], /Firefox\//);
                # print arr2[1]; # firefox version

                print arr1[1] + " " + arr1[2] + " " + "Firefox " + arr2[1];
                }
         }
}
