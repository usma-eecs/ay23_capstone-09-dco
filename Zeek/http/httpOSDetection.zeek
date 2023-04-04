# Attempting to model https://github.com/fatemabw/bro-scripts/blob/master/Mac-version-detection.bro

@load base/protocols/http
module OS;
export {
        redef enum Log::ID += { LOG };

        type osInfo: record {
                ip:     addr &log;
                os:     string &log;
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
        if (rec?$host && rec?$user_agent && /Linux/ in rec$user_agent) {
                if (/Chrome\// in rec$user_agent) {
                arr1 = split_string1(rec$user_agent, /\(/);
                arr2 = split_string1(arr1[1], / /);
                arr3 = split_string(arr2[1], /\)/);
                arr4 = split_string1(rec$user_agent, /Chrome\//);
                arr5 = split_string1(arr4[1], / /);

                print arr3[0] + " " + "Chromium " + arr5[0];
                Log::write(OS::LOG, [
                        $ip=rec$id$orig_h,
                        $os=arr3[0] + " " + "Chromium " + arr5[0]]);
                }
                else if ("Firefox/" in rec$user_agent) {
                arr1 = split_string_n(rec$user_agent, /\; /, F, 3);
                arr2 = split_string1(arr1[3], /Firefox\//);
                Log::write(OS::LOG, [
                        $ip=rec$id$orig_h,
                        $os=$name=arr1[1] + " " + arr1[2] + " " + "Firefox " + arr2[1]]);
                }
         }
}
