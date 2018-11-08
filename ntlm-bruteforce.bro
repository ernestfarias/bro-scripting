## bruteforcing over NTLM. based on NTLM over SMB , read NTLM auth at https://msdn.microsoft.com/en-us/library/cc669093.aspx
## if someone does that one for kerberos, let me know ;)
## Author Ernest A Farias 2018

@load base/frameworks/sumstats
@load base/frameworks/notice


module NTLM;

export {
        redef enum Notice::Type += {
                User_Password_Bruteforce,
        };
        ## guessing passwords limit.
        const password_guesses_limit: double = 8 &redef;

        ## model time.
        const guessing_timeout = 5min &redef;

        const ignore_guessers: table[subnet] of subnet &redef;


}

event bro_init()
        {
        local r1: SumStats::Reducer = [$stream="ntlm.login.failure", $apply=set(SumStats::SUM, SumStats::SAMPLE), $num_samples=8];
        SumStats::create([$name="detect-ntlm-bruteforcing",
                          $epoch=guessing_timeout,
                          $reducers=set(r1),
                          $threshold_val(key: SumStats::Key, result: SumStats::Result) =
                                {
                                return result["ntlm.login.failure"]$sum;
                                },
                          $threshold=password_guesses_limit,
                          $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
                                {
                                local r = result["ntlm.login.failure"];
                                local sub_msg = fmt("Detailed samples: ");
                                local samples = r$samples;
                                for ( i in samples )
                                        {
                                        if ( samples[i]?$str )
                                                sub_msg = fmt("%s%s %s", sub_msg, i==0 ? "":",", samples[i]$str);
                                        }
                                # Generate the notice.
                                NOTICE([$note=User_Password_Bruteforce,
                                        $msg=fmt("%s appears to be guessing Microsoft NTLM user passwords with at least %d failed attempts.", key$host, r$num),
                                        $sub=sub_msg,
                                        $dst=to_addr(key$str),
                                        $src=key$host,
                                        $suppress_for=2min,
                                        #$identifier=cat(key$host)]);
                                        $identifier=cat(samples[0]$str)]);
                                }]);
        }

        event smb1_message(c: connection, hdr: SMB1::Header, is_orig: bool) &priority=0
                {

                #get NTLM entries with failures
                 if ( c?$ntlm && ! c$ntlm$success &&
                     ( c$ntlm?$username || c$ntlm?$hostname ) )
                {
                #observe events
                local id = c$id;

               if ( ! (id$orig_h in ignore_guessers &&
                       id$resp_h in ignore_guessers[id$orig_h]) )
                       SumStats::observe("ntlm.login.failure", [$host=id$orig_h,$str=cat(id$resp_h)],
                                [$str=cat("Username: ",c$ntlm$domainname,"\\",c$ntlm$username
                                )]);
        }


                }

        event smb2_message(c: connection, hdr: SMB2::Header, is_orig: bool) &priority=0
                {

                #get NTLM entries with failures
                 if ( c?$ntlm && ! c$ntlm$success &&
                     ( c$ntlm?$username || c$ntlm?$hostname ) )
                {

                #observe events
                local id = c$id;

               if ( ! (id$orig_h in ignore_guessers &&
                       id$resp_h in ignore_guessers[id$orig_h]) )
                       SumStats::observe("ntlm.login.failure", [$host=id$orig_h,$str=cat(id$resp_h)],
                                [$str=cat("Username:",c$ntlm$domainname,"\\",c$ntlm$username, " From:", c$ntlm$hostname
                                )]);
        }

                }
