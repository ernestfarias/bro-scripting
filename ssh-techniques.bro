# SSH Interactive Shell Detection and Out connections
# Ernesto A Farias 2018, I've just improved Althouse script

redef SSH::disable_analyzer_after_detection = F ;

redef enum Notice::Type += {Reverse_SSH,SSH_Outgoing_Connection};

#counters by conn
global lssh_conns:table[string] of count &redef;
global linux_echo:table[string] of count &redef;
#echo lenght for current conn
global curr_echo_len:table[string] of int &redef;
#standard SSH echo lenghts, extend the list, a length calculator could be made for each hmac and enc type
const standard_echo_len = [76,84,96,98] &redef;

event ssh_server_version(c: connection, version: string)
{
  if ( c$uid !in lssh_conns )
  {
	lssh_conns[c$uid] = 0;
	linux_echo[c$uid] = 0;
    curr_echo_len[c$uid] = 0;
  }
  if ( c$uid !in linux_echo )
  {
    linux_echo[c$uid] = 0;
  }
}

event ssh_encrypted_packet(c:connection, orig:bool, len:count)
{
#DEBUG
# print("ENCPACKET-len");
# print(len);
# print(cat(c$uid," ",c$id$orig_h,"  ",c$id$resp_h , " orig:",orig," currlen:",curr_echo_len[c$uid]));
#/debug

#Notice when Ext Conn, only if 1 is local. bro doesn't have XOR
if ( (Site::is_local_addr(c$id$orig_h) || Site::is_local_addr(c$id$resp_h)) &&  !( Site::is_local_addr(c$id$orig_h) && Site::is_local_addr(c$id$resp_h)) )
    {
        local details = cat("SSH Server:",c$ssh$server," SSH Client:",c$ssh$client," Cipher:",c$ssh$cipher_alg);
        #DEBUGGER
        #print(sshdetails);
      NOTICE([$note=SSH_Outgoing_Connection,
            $conn = c,
            $msg = fmt("External connection from: %s:%s to %s:%s", c$id$orig_h,c$id$orig_p,c$id$resp_h,c$id$resp_p),
            $sub = fmt(" %s - %s", details,c$uid),
            $identifier=cat(c$uid),
            $suppress_for=1hrs
          ]);
    }

#Guess SSH Reverse, count echoes with same value
#1st packet if belog to a possible length for echo on rssh
if ( orig == F && len in standard_echo_len && lssh_conns[c$uid] == 0 )
  {
        lssh_conns[c$uid] += 1;
        curr_echo_len[c$uid] = len;
        return;
  }

if ( orig == T && len == curr_echo_len[c$uid] && lssh_conns[c$uid] == 1 )
{
  	lssh_conns[c$uid] += 1;
	return;
}

if ( orig == F && len == curr_echo_len[c$uid] && lssh_conns[c$uid] >= 2 )
  {
        lssh_conns[c$uid] += 1;
	return;
  }
if ( orig == T && len == curr_echo_len[c$uid] && lssh_conns[c$uid] >= 3 )
{
	lssh_conns[c$uid] += 1;
	return;
}

if ( orig == T && len > curr_echo_len[c$uid] && lssh_conns[c$uid] >= 10 )
{
	lssh_conns[c$uid] += 1;
	linux_echo[c$uid] = 1;
}

else { lssh_conns[c$uid] = 0; return; }

if ( c$uid in linux_echo )
  {
    if ( linux_echo[c$uid] == 1 )
    {
        local sshdetails = cat("SSH Server:",c$ssh$server," SSH Client:",c$ssh$client," Cipher:",c$ssh$cipher_alg);
        #DEBUGGER
        #print(sshdetails);
        local char = ((lssh_conns[c$uid] / 2) - 1);
      NOTICE([$note=Reverse_SSH,
            $conn = c,
            $msg = fmt("Possible Reverse SSH Shell from: %s to %s:%s", c$id$orig_h,c$id$resp_h,c$id$resp_p),
            $sub = fmt("with %s characters echoed. %s", char, sshdetails),
            $identifier=cat(c$id$orig_h)
            #$suppress_for=1hrs
          ]);
     linux_echo[c$uid] = 0;
     lssh_conns[c$uid] = 0;
    }
  }
}
