#look if dns servers are not in a whitelist
#author: Ernesto A Farias
@load base/frameworks/notice
#Notice when a query is requeted to a DNS that is not in DNS_SERVER

module DNS;

const dns_servers: set[addr] = {
	192.168.33.1,
	192.168.32.1,
} &redef;

const dns_ignore: set[addr] = {
	192.168.33.255,
	224.0.0.252,
	224.0.0.251,
} &redef;

const dns_port_ignore: set[port] = {
	5353/udp,
	137/udp,
} &redef;

export {

        redef enum Notice::Type += {
                DNS::Not_Allowed_DNS_Server_Usage
        };
}

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
        {

	# Exit event handler if originator is not in networks.cfg
	if (! Site::is_local_addr(c$id$orig_h) )
		return;

	# Exit event handler if originator is an ignore address
	if ( c$id$orig_h in dns_ignore )
		return;

	# Exit event handler if originator is our local dns server
	if ( c$id$orig_h in dns_servers )
		return;

	# Exit event handler if port is a ignored DNS port
	if ( c$id$resp_p in dns_port_ignore )
		return;

        if ( c$id$resp_h !in dns_servers )
                {
                NOTICE([$note=DNS::Not_Allowed_DNS_Server_Usage,
                $msg="DNS Request destined to a non authorized DNS server", $conn=c,
                $identifier=cat(c$id$orig_h,c$id$resp_h),
                $suppress_for=1day]);
                }
}
