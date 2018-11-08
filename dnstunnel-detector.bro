# guess dns tunnes, by checking abn pkt sizes and abn queries lenght
# Author: Ernest Farias
@load base/frameworks/input
@load base/protocols/dns
@load base/frameworks/notice

module DNS;

export {
    redef enum Notice::Type += {
        DNS::Tunneling
        };
       }
# ignore broadcast addresses
const dns_ignore: set[addr] = {
    224.0.0.252,
	224.0.0.251,
    [ff02::fb],
    } &redef;

# default suppress time for all notices before 20min
const suppress_time_notices = 2day;
# DNS queries to not alert on, TODO see if need to add spotify as they use dns tunneling techniques to transfer stream
const ignore_DNS_names = /\.local|wpad|isatap|autodiscover|gstatic\.com$|domains\._msdcs|mcafee\.com$/ &redef;
# size at which dns query domain name is considered interesting, can use another var with a regexp, more complicate coding
const dns_query_oversize = 90 &redef;
# query types to not alert on 12 ptr reverse and 32 netbios
const ignore_qtypes = [12,32] &redef;
# total DNS payload size over which to alert on, more than 512 is suspicious
const dns_plsize_alert = 512 &redef;
# ports to ignore_DNS_names
const dns_ports_ignore: set[port] = {137/udp, 137/tcp} &redef;
# dnstunnel, period where count packets that are larger than dns_plsize_alert, interval type
const epoch_tunnel_plsize = 2min &redef;
# count of packets larger than dns_plsize_alert during a period of epoch_tunnel_plsize, count type
const count_of_large_packets = 12.0 &redef;
# config file that contains legitimate regular expected dns servers used in my network, normalt dns provided by the isp and router ip addrr
const regular_dns_file = "./regular_dns.txt" &redef;
# }
#TOOO DOOO , store legitimate DNS, for filtering purpouses
# Table to store list of domains in file above
#global regular_dns_table: set[string];
# Record for domains in file above
#type regular_dns_idx: record {
#  regular_dns: string;
#};

event bro_init()
    {
    local r1 = SumStats::Reducer($stream="Detect.dnsTunneling", $apply=set(SumStats::SAMPLE), $num_samples=3);
    SumStats::create([$name="Detect.dnsTunneling",
			$epoch=epoch_tunnel_plsize,
			$reducers=set(r1),
			$threshold = count_of_large_packets,
			$threshold_val(key: SumStats::Key, result: SumStats::Result) =
				{
                    #debugger
                    #print result["Detect.dnsTunneling"]$num+0.0;
                    return result["Detect.dnsTunneling"]$num+0.0; # trigger when reach threshold - +0.0 to make datatype compatble
				},
                $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
                {
                    #DEBUGGER
                    #print "CROSS TRH, DO NOTICE key:" + key;
                    local r = result["Detect.dnsTunneling"];
                    local samples = r$samples;
                    local sub_msg2 = "Detected on:";
                    local total_bytes = 0;
                    #print samples;
                    for ( i in samples )
                    {
                        if ( samples[i]?$str )
                               sub_msg2 = fmt("%s%s %s", sub_msg2, i==0 ? "":",", samples[i]$str);
                               #sum bytes
                        if ( samples[i]?$num )
                               total_bytes = total_bytes + (samples[i]$num);
                          }
                          #print "bytes received:" total_bytes;
                           local parts = split_string(key$str, /,/);
                           #DEBUGGER
                           #print "test parts" + parts[1];
                  NOTICE([$note=DNS::Tunneling,
                      $msg=fmt("Possible DNS Tunnel, large consecutive DNS responses detected from %s" ,key$host),
                      $sub=(sub_msg2 + fmt(". Total Large Bytes: %s", total_bytes)),
                      $src=key$host,
                      $identifier=cat(key$host),
                      $dst=to_addr(parts[1]),
                      $suppress_for=suppress_time_notices
                      ]);
                  }
        ]);
    }
event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
    {
        if (qtype !in ignore_qtypes && c$id$resp_p !in dns_ports_ignore && c$id$resp_h !in dns_ignore)
        {
            if (|query| > dns_query_oversize && ignore_DNS_names !in query)
            {
                SumStats::observe("Detect.dnsTunneling",
                [$host=c$id$orig_h,
                    $str=cat(
                        c$id$orig_p,",",
                        c$id$resp_h,",",
                        c$id$resp_p,",",
                        c$uid)],
                        [$str=cat("Query: ",query)]);
                        #print "Hit Large Qry: query";
                    }
                }
            }

# ON DNS SERVER REPLY BACK
event dns_message(c: connection, is_orig: bool, msg: dns_msg, len: count)
	  {
          if (len > dns_plsize_alert && c$id$orig_p !in dns_ports_ignore && c$id$resp_h !in dns_ignore)
	          {
		               SumStats::observe("Detect.dnsTunneling",
                       [$host=c$id$orig_h,
                           $str=cat(
                               c$id$orig_p,",",
                               c$id$resp_h,",",
                               c$id$resp_p,",",
                               c$uid)],
                               [$num=len]);

    }
}
