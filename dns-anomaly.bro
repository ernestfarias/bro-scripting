#Report on anomaly amount of NXDOMAINS returned from a DNS
#Author Ernest Farias (c) 2017
@load base/frameworks/input
@load base/protocols/dns
@load base/frameworks/notice
#module DNS;
export {
        redef enum Notice::Type += {
                DNS::Multiple_Domain_Not_Found                
        };
     }
const suppress_time_notices = 24hrs;
const ignore_DNS_names = /\.local|wpad|isatap|autodiscover|gstatic\.com$|domains\._msdcs|mcafee\.com$/ &redef;
const ignore_qtypes = [12,32] &redef;
const dns_ports_ignore: set[port] = {137/udp, 137/tcp} &redef;
const epoch_nxdomains = 1min &redef;
const count_of_nxdomains = 10.0 &redef;

event DNS::log_dns(rec: DNS::Info)
{
  #is the src or dest host in the internal
     if ( !Site::is_local_addr(rec$id$orig_h) && !Site::is_local_addr(rec$id$resp_h) )
            {
            return;
            }
                    # do these fields exist?
     if (rec?$rcode_name && rec?$qtype)
            {
          if (to_upper(rec$rcode_name) == "NXDOMAIN" && rec$qtype !in ignore_qtypes && to_upper(rec$qclass_name) == "C_INTERNET" && ignore_DNS_names !in to_lower(rec$query))
              {
                SumStats::observe("Detect.dnsNXDOMAIN2",[$host=rec$id$orig_h],[$str=cat(rec$query)]);
              }
            }
   
}

event bro_init()
    {
      local r2 = SumStats::Reducer($stream="Detect.dnsNXDOMAIN2", $apply=set(SumStats::UNIQUE, SumStats::SAMPLE), $num_samples=10);
      SumStats::create([$name="Detect.dnsNXDOMAINunique",
 			$epoch=epoch_nxdomains,
 			$reducers=set(r2),
 			$threshold_val(key: SumStats::Key, result: SumStats::Result) =
 				{
        #debugger
        #print result["Detect.dnsNXDOMAIN2"];
      	return result["Detect.dnsNXDOMAIN2"]$unique+0.0;

 				},
             $threshold=count_of_nxdomains,
 			$threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
 				{
                     local r = result["Detect.dnsNXDOMAIN2"];
                          local samples2 = r$unique_vals;
                          local sub_msg2 = "";
                          for ( k in samples2 )
  	                  		{
  	                  		sub_msg2 = fmt("%s, %s", sub_msg2 ,k$str);
  	                  		}
                   	NOTICE([$note=DNS::Multiple_Domain_Not_Found,
 	                  	        $msg=fmt("The host %s Has tried to contact multiple different unreachable domains names in less than %s", key$host,epoch_nxdomains),
 	                  	        $sub=sub_msg2,
 	                  	        $src=key$host,
 	                  	        $identifier=cat(key$host),
                              $suppress_for=suppress_time_notices

 				]);
 					}]);
    }
