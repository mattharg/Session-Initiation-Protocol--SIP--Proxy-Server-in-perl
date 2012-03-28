#!/usr/bin/perl -W
# Author                Matthew Hargreaves  
# Title                 SIP Proxy Server 
# File                  SIP_proxy.pl   
# Print Using           a2ps -E -2  -P pslpd 
my $Release="3";
my $Version='$Revision: 1.27 $'; $Version =~ s/\$//g;
# ToDo                  o Use syslog for reporting
#                       o Generate CORRECT branch i/ds  
#                       o Detect addressing to SELF, and do a REGISTER LOOKUP
#                         rather than send a UDP message to self - STUPID....
#                       o Integrate with REGISTER Server
#                       o q. Include own's REGISTER service 
#                       o SOAP - Introduce it.....
#                       o Other Methods - Code them...
#                       o SIP Response Messages - how to deal with them???
#                       o 
#                       o ? Use const pragmatic module
#                       o Investigate the perl compiler.
#                       o GOTTA forward these RINGING...
#                       o q/ Implement Config. File. Parsing.
#                       o 
#                       o If I have received ONE INVITE and have proxied it,
#                          - I need to note that this is in progress and,
#                            if I received any more duplicate INVITE's  not
#                            create a new branch......
#                       o 
#                       o 
# Problems
#                       - Gotta detect UA resent UDP messages, and not proxy
#                         with a new branch no. 
#                         How?
#                           o Should I detect and ignore, -or-, resend my
#                             previous message?
#                           o Could keep a hash of current calls, and test
#                             against it for each new proxied call.
#                           o 
#                           o 
#                       - 
#                       - UA's may NOT use the Contact: header to bypass the 
#                         proxy, and therefore send their ACK etc. to the
#                         proxy.
#                       - 
#                       - 
# Notes                 o Naming
#                       o $..._msg       is a perl multi-line string containing the CRLFs
#                       o @..._msg_lines is a perl array of strings each containing
#                                        single (unterminated) lines.
#                       o
#                       o
# History               x Rel 1:  Basic Proxying Working.  Had to 
#                                 - Not proxy a 'Ringing' as the UA carp'd it
#                                 - Proxy the method ACK, as the UA was dumb to
#                                   the Contact: line it had received.
#                         Rel. 2: SOAP Via: Rewriting / substitution working.
#                                 -
#                                 -
# SUBroutines           +
#
use strict;
use Sys::Hostname;
use Socket;
use IO::Socket;
use Sys::Syslog;
use Net::DNS;

# Forward Decs
#------------
sub logit; sub TruthValue;

# - Constants
# -----------
my $SIPVer="2.0";
my $MYHOSTNAME="sipldap.sigstd.CHANGE_ME.com.au" ;  #!Find an automatic way.....
##my $MAXLEN=1024;
my $MAXLEN=2048;
my $STD_SIP_PORTNUM=5060;
my $CRLF="\r\n";
my $Me="SIP_Proxy";
my $MYSERVERLINE="Server: CHANGE_ME $Me SIP $SIPVer Release $Release $Version";
my $MYTRYINGLINE='SIP/2.0 100 Trying';
my $MYNOTFOUNDLINE='SIP/2.0 404 Not Found';
my $IP_ADDR_NOT_RESOLVED='0.0.0.0';
my $REGEXP_VIA_HEADERS='^Via:';


# - Globals
# ---------
my($recv_sock, $oldmsg, $new_msg, $hisaddr, $hishost);
my(@new_msg_lines);
my($hostname, $hostip);
my $MyPort=$STD_SIP_PORTNUM;
my $MyBranch="000111";
my $MYVIALINE_BASE;
my $MyViaLine;

# - Configuration Flags
# ---------------------
my $FLAG_SOAP=0;                 # Implement SOAP Functionality
my $FLAG_DO_REDIRECT=0;          # Implement interface to a REDIRECDT SERVER 
my $FLAG_BE_A_REDIRECT_SERVER=0; # Implement own redirect server facility;

# - Configuration
# ---------------
my $DNS_DOMAIN='sigstd.CHANGE_ME.com.au'; # DNS Domain for the outbound proxy server 
my $argv_list= join " ",  @ARGV;
my $MyHostName;

sub configure {

	my $Usage="
NAME
	$Me -  CHANGE_ME SIP Proxy Server With SOAP Facilities
SYNOPSIS
	$Me { -flags } 
DESCRIPTION
	Invokes the proxy server.
	-h                        Give this help.
	-SOAP                     Incorporate the SOAP functionality.
	-DO_REDIRECT              Do redirections for this DNS domain.
	-INBUILT_REDIRECT_SERVER  Use inbuilt redirect server.
	-USE_PORT nnnn            Use nnnn as port number instead of $STD_SIP_PORTNUM.
	-DNS_DOMAIN dom1.dom2     The DNS domain for the outbound proxy server 
	                          and also for SOAP. 
";

	$hostname=hostname(); 
	$hostip=gethostbyname($hostname);
	$MyHostName=gethostbyaddr($hostip, AF_INET);
	$MYVIALINE_BASE="Via: SIP/2.0/UDP $MyHostName:$MyPort;branch=";

	my $argv;
##	foreach my $argv (@ARGV) {
		my $arg_n=0; 
		while ($argv=$ARGV[$arg_n++]) {
		   if ($argv =~ m/-SOAP/)                    { $FLAG_SOAP=1; }
		elsif ($argv =~ m/-DO_REDIRECT/)             { $FLAG_DO_REDIRECT=1; }
		elsif ($argv =~ m/-INBUILT_REDIRECT_SERVER/) { $FLAG_BE_A_REDIRECT_SERVER=1; }
		elsif ($argv =~ m/-USE_PORT/)                { $MyPort=$ARGV[$arg_n++]; }
		elsif ($argv =~ m/-DNS_DOMAIN/)              { $DNS_DOMAIN=$ARGV[$arg_n++]; }
		elsif ($argv =~ m/-h/)                       { print "$Usage"; }
		else {
			die "$Me: Error: Unknown argument:$argv\n";
		}
	}
}

sub dump_config {
	logit "debug", "Config: My proxy server Name is: $MyHostName \n";
	logit "debug", "Config: Acting As SOAP Server:   %s\n", &TruthValue($FLAG_SOAP);
	logit "debug", "Config: Using Redirect Server:   %s\n", &TruthValue($FLAG_DO_REDIRECT);
	logit "debug", "Config: InBuilt Redirect Server: %s\n", &TruthValue($FLAG_BE_A_REDIRECT_SERVER);
	logit "debug", "Config: Port Used:               %s\n", $MyPort;
	logit "debug", "Config: DNS Domain for Proxy:    %s\n", $DNS_DOMAIN;
	logit "debug", "Config: Invoked with arguments:  $argv_list\n";
}
	

# -----------------------------   S u p p o r t     F n s    ---------------------------- #
sub TruthValue {
	($_[0]) ? return "True" : return "False";
}

my $REGEXP_SyslogLevel='^(emerg|alert|crit|err|warning|notice|info|debug)$';

sub logit {
# Eg. &syslog "notice", "%s\n", "a string";  # AND %m == $!
	my $sl_level=shift;   $sl_level="warning" if ($sl_level !~ $REGEXP_SyslogLevel);
	my $pfstr=shift;
	my $sl_pfstr="$pfstr [%m]";
	my @sl; push @sl, $sl_level, $sl_pfstr, @_;

	&openlog("US_LOT SIP PROXY", "ndelay", "local6"); 
	syslog(@sl);
	&closelog;

	$pfstr="$Me: $sl_level: $pfstr"; 
	my $logit=sprintf($pfstr,  @_);
	printf $logit; 
}

# - Data Formats 
# --------------------
# @....msg_lines :: An array of Non-terminated strings, each representing a line.
# $....sipmsg    :: A single string representing a multi-line SIP message, with
#                   lines terminate by CRLF.
sub dump_msg_lines {  # $preamble, @...msg_lines
	my $preamble=shift;

	my ($n); for ($n=0; (defined($_[$n])); $n++) {
		logit "debug", sprintf("%s: %03d---%s---\n", $preamble, $n, $_[$n]);
	}
	logit "debug", "\n";
}

sub lines_to_sipmsg {
# Convert the supplied array of perl lines (no termination char's) 
# into a SIP msg, one multi-line perl string with CRLF terminated lines.
		return ( join $CRLF, @_ ) . $CRLF;
}

sub sipmsg_to_lines {
# Convert the supplied SIP msg, one multi-line perl string with CRLF terminated lines, to 
# an array of perl lines (each with no termination char's) 
# 
	my $msg=$_[0];
	my @lines=split /\n/, $msg;  # Take the SIP message and split into array of lines
	chomp(@lines);                # Remove the   \n off each line
	chop(@lines);                 # Remove (any) \r off each line
##		@new_msg_lines= map  "=~ s/\r//g",   @new_msg_lines; # Remove (any) \r off each line
##		foreach (@new_msg_lines) {   "=~ s/\r//g",   @new_msg_lines; # Remove (any) \r off each line
##		@new_msg_lines= map  '$_ =~ s/\r//g',   @new_msg_lines; # Remove (any) \r off each line
	return @lines;
}

sub filter_msg_lines { # $RegExp, @lines_to_filter
# Converts the supplied array of lines into one that ONLY match the $RegExp
# I guess this is GREP functionality!!!!
	my $RegExp=shift;

	my(@FilteredLines, $line);
	foreach $line (@_) {
		push @FilteredLines, $line  if ($line  =~ $RegExp);
	}
	return @FilteredLines;
}

sub rev_filter_msg_lines { # $RegExp, @lines_to_filter
# Converts the supplied array of lines into one that ONLY DOES NOT match the $RegExp
# I guess this is GREP -v functionality!!!!
	my $RegExp=shift;

##	logit "debug", "rev_filter RegExp: $RegExp \n";
##	dump_msg_lines "Reverse Filter source", @_;
	my(@FilteredLines, $line);
	foreach $line (@_) {
		push @FilteredLines, $line  if ($line  !~ $RegExp);
	}
##	dump_msg_lines "Reverse Filter result", @FilteredLines;
	return @FilteredLines;
}

sub prepend_msg_lines {
}

sub replace_msg_lines { # $SipMsg, $matchlines_sigmsg, $replacementlines_sipmsg 
}



# ------------------------------------- S O A P --------------------------------
# Title:               SOAP: SIP On-Air Proxy
# Goal:                Reduce On-Air (mobile) bandwidth, between mobile device
#                      and SIP Proxy.
# Description:
#   Between the UA and the Proxy Server, or embedded within the Proxy Server,
#
#   (1.a) Replace the long via lists of the network with single via line to the UA, and
#   convert back again on the other side.
#   (1.b) This also requires simillar mechanism with the RecordRoute and Route
#   messages.
#
#   (2) Filter out headers that the UA would not take notice of anyway, eg.
#   Organisation, etc.  Should this filtering be dependent on the destination,
#   eg.
#       o The IP of the Destination (Shouldn't infiltrate other protocol layers)
#       o The username in the request URI (But users move between devices)
#       o Some other matching on the DNS name?, eg.
#         sipuser2@dev44_dumbdevice.domain.com.au
#       o Some DNS supplied device characteristic
#       o Some device characteristic from a DEVICE registration server, along
#         simillar lines to the USER registration server .............
#         Here, however, you need to get the UA device to participate in the
#         registration.....
#       o 

my $REGEXP_INVITE_THIS_DOMAIN=sprintf "^INVITE\\s+sip:\\S+@\\S+\.%s\\s", $DNS_DOMAIN; # Will SOAP Invite: messages to this domain;

my $REPLACED_VIA_BASE = "Via: SIP/2.0/UDP $MYHOSTNAME:$MyPort;branch=SOAP";
my $soap_index=0;       # SOAP index of each new Transform

my
$REGEXP_SOAP_Header_Filter='^(Date|Organization|Organisation|User-Agent|Expires|Priority|Subject|Call-Info):';

my %SOAP_Via_Transform; # Hash of Via Transforms for SOAP
sub dump_SOAP_Via_Transform {
	foreach my $soapline (keys %SOAP_Via_Transform) {
		logit "info", "SOAP: Original Line: $soapline\n";  
		logit "info", "SOAP: Replaced with\n";  
		foreach my $origline (sipmsg_to_lines($SOAP_Via_Transform{$soapline})) {
			logit "info", "SOAP: \t$origline\n";  
		}
	}
}

sub UNSOAP_msg_lines { 
# Takes an array of lines, and replaces all the 'Via:' lines with
# one new, unique, 'Via:' line, thus implementing SOAP.
# and returns this new array of lines;
	my @RecvViaList= filter_msg_lines     $REGEXP_VIA_HEADERS, @_;

	my @unsoaped_lines;  # What I will return;

	if ($#RecvViaList != 0) {
		logit "err", "SOAP: Can not UnSOAP these Via: lines.  There is %d of them\n", 1+$#RecvViaList;  
		return @_;
	} else {
		foreach my $line (@_) {
			if ($line =~ $REPLACED_VIA_BASE) {
				push @unsoaped_lines, sipmsg_to_lines($SOAP_Via_Transform{$RecvViaList[0]});
			} else {
				push @unsoaped_lines, $line;
			}
		}
		return @unsoaped_lines;
	}
}

sub SOAP_msg_lines { 
# Takes an array of lines, and replaces all the 'Via:' lines with
# one new, unique, 'Via:' line, thus implementing SOAP.
# and returns this new array of lines;

##	&dump_msg_lines("DIRTIED", @_);

	my @NewLines      = rev_filter_msg_lines $REGEXP_VIA_HEADERS, @_;  # Remove Ori Via: list
	my @ViaList       =     filter_msg_lines $REGEXP_VIA_HEADERS, @_;

	$soap_index++;
	my $ReplacedVia   = "$REPLACED_VIA_BASE$soap_index.XX";
	$SOAP_Via_Transform{$ReplacedVia}=lines_to_sipmsg(@ViaList);

##	dump_msg_lines("ViaList",     @ViaList);
##	dump_msg_lines("ReplacedVia", $ReplacedVia);

	my $OldViaPosn=0; 
	while ($_[$OldViaPosn] !~ $REGEXP_VIA_HEADERS && $OldViaPosn <= $#_) {
		$OldViaPosn++;
	}
	if ($OldViaPosn > $#_) { 
		logit "err", "SOAPing: Could not find the first Via: line\n";
		&dump_msg_lines("DIRTIED", @_);
	}

	splice(@NewLines, $OldViaPosn, 0, $ReplacedVia);  # Insert the Replaced Via:
	@NewLines=rev_filter_msg_lines $REGEXP_SOAP_Header_Filter, @NewLines;    # Remove Unnecessary headers;
##	&dump_msg_lines("SOAPed:NewLines", @NewLines);
	return @NewLines;
}

sub SOAP_sipmsg {
	return lines_to_sipmsg(  SOAP_msg_lines(sipmsg_to_lines($_[0])));
}

sub UNSOAP_sipmsg {
	return lines_to_sipmsg(UNSOAP_msg_lines(sipmsg_to_lines($_[0])));
}


# ----------------------------   P a r s i n g   -----------------------------------
my $REGEXP_CALL_LEG_HEADERS='^(To|From|Call-ID|CSeq):';
my $REGEXP_CALL_LEG_AND_VIA_HEADERS='^(To|From|Call-ID|CSeq|Via):';
my $REGEXP_IP_ADDR='(\d+\.\d+\.\d+\.\d+)';
my $REGEXP_IP_AND_PORT_ADDR='(\d+\.\d+\.\d+\.\d+):(\d+)';

sub parse_IP_and_port {
# Takes a single line, containing,
#   o nnn.nnn.nnn.nnn{:mmmm}
# and returns
# 1        2
# IP_Addr  Port_Num
#
  my $line=shift;
	logit "debug", "Parsing for IP and port: $line \n" ;
	$line          =~  m{ $REGEXP_IP_AND_PORT_ADDR }x; # Match the IP and Port
	my $IP_Addr    = "$1";
	my $PortNum    = "$2";
	logit "debug", "Parsed IP_Addr $IP_Addr Port_Num $PortNum \n";
	return $IP_Addr, $PortNum	
}

sub parse_rHOSTrDOMAIN {
# Take a single line , containing
#   o host.domain1.domain2{:pppp}
# and returns
# 1                      2       3                4                     
# rHOSTrDOMAIN           rHOST   rDOMAIN          PortNum
# Eg. 
# sip3.server.domain.com sip3    domain.com       5060

	my $line=shift;

	logit "debug", "Parsing for rHOSTrDOMAIN: $line \n" ;

	   $line           =~  s{ (\S+):(\d+)  } "$1\@$2"x; # Extract the rHOSTrDOMAIN
	my $rHOSTrDOMAIN   =   defined($1) ? "$1" : "$line"; 
	my $PortNum        =   defined($2) ? "$2" : $STD_SIP_PORTNUM;
	   $rHOSTrDOMAIN   =~  m{ ^ ([^.]+) . (\S+)  $ }x; # Extract the rHOST
	my $rHOST          =  "$1";
	my $rDOMAIN        =  "$2"; 

	$PortNum = $STD_SIP_PORTNUM if ( (!defined($PortNum))  || ($PortNum =~ '^$'));
	logit "debug", "Parsed rHrD $rHOSTrDOMAIN rH $rHOST rD $rDOMAIN PortNum $PortNum \n";
	return ($rHOSTrDOMAIN, $rHOST, $rDOMAIN, $PortNum );
}

sub parse_SIP_URI {
	# Take a single line string contain a sip URI, such as,
	#   o INVITE sip:sipuser3@sip3.domain.com SIP/2.0
	#   o INVITE sip:sipuser3@146.11.12.181 SIP/2.0
	# and returns,
	# 1                       2      3                4                     5
	# rHOSTrDOMAIN            rHOST  rDOMAIN          sipURI                Username 
	# Eg. 
	# sip3.us.domain.com      sip3    them.domain.com  sip3.us.domain.com   sipuser3

	my $line=shift;

	logit "debug", "Parsing SIP URI line $line \n" ;


	   $line           =~  s{ sip: ([^@]+) @ (\S+)  } "$1\@$2"x; # Extract the sipURI
	my $sipURI         =  $line;
	my $Username       =  "$1"; 
	my $rHOSTrDOMAIN   =  "$2"; 
	   $rHOSTrDOMAIN   =~  m{ ^ ([^.]+) . (\S+)  $ }x; # Extract the rHOST
	my $rHOST          =  "$1";
	my $rDOMAIN        =  "$2"; 
	logit "debug", "Parsed rHrD $rHOSTrDOMAIN rH $rHOST rD $rDOMAIN sipURI $sipURI username $Username \n";
	return ($rHOSTrDOMAIN, $rHOST, $rDOMAIN, $sipURI, $Username);
}


# --------------    M e s s a g e    H a n d l i n g    S u p p  o r t -- -------

sub Resolve_IP_or_rHOSTrDOMAIN {
	# Take a single line either like, 
	#   o Via: SIP/2.0/UDP 146.11.84.45:5060
	#       - or - 
	#   o Via: SIP/2.0/UDP proxy.munich.de:5060
	# and returns
	# 1        2
	# IP_Addr  Port_Num

	my $line=shift;

	logit "debug", "Resolving IP_or_rHrD for line: $line \n" ;

	my($rHOSTrDOMAIN, $rHOST, $rDOMAIN, $PortNum, $IP_addr);
	my(@dd);

	if ($line =~ $REGEXP_IP_ADDR) { 
		($IP_addr, $PortNum)=parse_IP_and_port $line; 
	}
	else { # Assume addressing is DNS
		($rHOSTrDOMAIN, $rHOST, $rDOMAIN, $PortNum) = parse_rHOSTrDOMAIN $line;
		if (@dd=gethostbyname($rHOSTrDOMAIN)) { 
			$IP_addr=inet_ntoa($dd[4]);
		} else {
			$IP_addr=$IP_ADDR_NOT_RESOLVED;
		}
	}
	logit "debug", "Resolved (IP is $IP_addr, Port is $PortNum) IP_or_rHrD for line: $line \n" ;
	return $IP_addr, $PortNum;
}

sub send_using_IP_and_port { # IP, Port, SIP_Message
	my $IP_str=shift;
	my $Port=shift;
	my $SIP_Message=shift;


	if ($IP_str =~ $IP_ADDR_NOT_RESOLVED) {
		logit "err", "$IP_str:$Port\n";
		return;
	}

	my $Sock_Addr=sockaddr_in($Port, inet_aton($IP_str));

	socket(SEND_SOCK, PF_INET, SOCK_DGRAM, getprotobyname("udp"))
		or die "$Me: Socket: $!\n";
	send(SEND_SOCK, $SIP_Message, 0, $Sock_Addr) == length($SIP_Message) 
		or die "$Me: Can NOT get socket for SEND MESSAGE: $@ ... $! ...";

	logit "info", "Sent mssg to $IP_str:$Port\n";
	dump_msg_lines("sent", sipmsg_to_lines($SIP_Message));
}

sub send_using_rHOSTrDOMAIN { # $rHOST, $rDOMAIN, $message
	# Spec:   Sends a message given a URI 
	# How:    o Parses the URI and tries in sequence
	#   - ip of DNS Addr for host       rHOST.rDOMAIN,   then 
	#   - ip of DSN SRV  for domain     rHOST.rDOMAIN,   then 
	#   - ip of DNS Addr for host   sip.rHOST.rDOMAIN,   then 
	#   - ip of DSN SRV  for domain           rDOMAIN,   then 
	#   - ip of DNS Addr for host         sip.rDOMAIN,   then 
	# Otherwise,
	#   - turn the message around to sender with a NOT FOUND (404) method.
	#
	# ToDo: Alter this to also 
	#   - Use a raw IP if supplied...
	#   - Contact a (local) Redirect Server if addr. is local...
	#
	#
	my $rHOST=shift;            #The host   part of where to send the message 
	my $rDOMAIN=shift;          #The domain part of where to send the message
	my $forward_msg=shift;      #The message to send 

	my $rHOSTrDOMAIN=$rHOST . "." . $rDOMAIN; #The host.domain string of where to send to
	my(@dd, $dd_address_num, $dd_address_str, $dd_sock_addr); # Desired Destination vars
##	local $MYLOCAL;
	my $l;

	sub DNS_SRV_query { # domain
		my $domain=shift;

		my($rr, $name);
		my $res = new Net::DNS::Resolver;
		my @srv= srv($res, $name);
		if (@srv) {
			foreach $rr (@srv) {
				print "Found SRV $rr->target:$rr->port \n";;
			}
		}
		else {
			print "Can't find SRV record for $domain\n";
		}
	}

	if ( (@dd=gethostbyname($rHOSTrDOMAIN))          ||
		   (@dd=gethostbyname("sip." . $rHOSTrDOMAIN)) ||
		   (@dd=gethostbyname("sip." . $rDOMAIN))    
		 ) {
		$dd_address_num=$dd[4];
		$dd_address_str=inet_ntoa($dd_address_num);
		$dd_sock_addr=sockaddr_in($STD_SIP_PORTNUM, $dd_address_num);
		logit "notice", "Forwarding Message: Addressed as: $rHOSTrDOMAIN\n";
		logit "notice", "Forwarding Message: Discovered:   $dd[0] (aliases:$dd[1])\n";
		logit "notice", "Forwarding Message: Using:        $dd_address_str:$STD_SIP_PORTNUM\n";
		socket(FORW_SOCK, PF_INET, SOCK_DGRAM, getprotobyname("udp"))
			or die "$Me: Socket: $!\n";
		send(FORW_SOCK, $forward_msg, 0, $dd_sock_addr) == length($forward_msg) 
			or die "$Me: Can NOT get socket for FORWARD INVITE: $@ ... $! ...";
	}
	else { # Can't find an IP for this URI, I'll have to turn around a 404 NotFound
		logit "warning", "NotFound 404: Cant Find IP or SIP server for $rHOSTrDOMAIN\n";
		my @NotFoundMsgLines;
		push @NotFoundMsgLines, $MYNOTFOUNDLINE;
##		push @NotFoundMsgLines, $MyViaLine; # NotFound DONT include the proxy's Via:
		push @NotFoundMsgLines, filter_msg_lines($REGEXP_CALL_LEG_AND_VIA_HEADERS, sipmsg_to_lines($forward_msg));
		push @NotFoundMsgLines, $MYSERVERLINE;
		$recv_sock->send(lines_to_sipmsg(@NotFoundMsgLines));   # Send back a NOT Fond  message
	}
}

# --------------------   M e s s a g e    G e n e r a t i o n   -----------------------

sub generate_MyBranch {
	$MyBranch++;  # We'll may get a better method later..
}

sub generate_MyViaLine {
# Generate a new $MyViaLine, ie. with a new $MyBranch

	&generate_MyBranch;
	$MyViaLine="$MYVIALINE_BASE$MyBranch";
}

sub generate_forward_msg_lines {
# Insert the via line, copy over all other lines

	my @forward_msg_lines;

	my $l=0; while ($l <= $#_ && $_[$l] !~ '^Via:') { 
		push @forward_msg_lines, $_[$l]; $l++;
	};
	push @forward_msg_lines, $MyViaLine;
	while ($l <= $#_) {
		push @forward_msg_lines, $_[$l]; $l++;
	};
	return @forward_msg_lines;
}

sub generate_trying_msg_lines {
# Takes the original @...msg_lines
# Inserts the Trying line and Via line, and copies over the call leg and via lines
# Returns the generated @..msg_lines
	my @trying_msg_lines;

	push @trying_msg_lines, $MYTRYINGLINE;
##	push @trying_msg_lines, $MyViaLine;  # Trying Messages DO NOT HAVE the proxy Via line ....

	push @trying_msg_lines, filter_msg_lines($REGEXP_CALL_LEG_AND_VIA_HEADERS, @_);
	push @trying_msg_lines, $MYSERVERLINE;
	return @trying_msg_lines;
}

sub generate_notfound_msg_lines {
	my     @NotFoundMsgLines;

	push   @NotFoundMsgLines, $MYNOTFOUNDLINE;
##	push   @NotFoundMsgLines, $MyViaLine;
	push   @NotFoundMsgLines, filter_msg_lines($REGEXP_CALL_LEG_AND_VIA_HEADERS, @_);
	push   @NotFoundMsgLines, $MYSERVERLINE;
	return @NotFoundMsgLines;
}

sub generate_SOAP_msg_lines_if_regexp {
	my $REG_EXP=shift;
	my @SOAP_hits=filter_msg_lines($REG_EXP, @_);

	my @ret_array;

	if ($#SOAP_hits == 0) {
		logit "info", "generate_SOAP_msg_lines_if_regexp: Detected ($#SOAP_hits hits)\n";
		@ret_array=SOAP_msg_lines(@_);
		dump_msg_lines("SOAP HITS", @SOAP_hits);  
	}
	else {
		logit "info", "generate_SOAP_msg_lines_if_regexp: NOT Detected ($#SOAP_hits hits)\n";
		@ret_array=@_;
	}
	return @ret_array;
}


# - Proxy Messages
# ----------------
sub proxy_sip_response_msg {
# Remove my top Via header and send to the now new top Via header.
#
	my @proxied_msg_lines=rev_filter_msg_lines $MYVIALINE_BASE, @_;
	my $NewDest;
	my $l=0; while ($l <= $#proxied_msg_lines && $proxied_msg_lines[$l] !~ $REGEXP_VIA_HEADERS) {
		$l++;
	};
	if ($l > $#proxied_msg_lines) {
		logit "err", "Could Not Find next Via: line while proxying\n"; 
		dump_msg_lines "proxied_failed", @proxied_msg_lines;
	} 
	else {
		logit "info", "proxy_sip_response: \n"; 
		dump_msg_lines "Proxied", @proxied_msg_lines;
		$NewDest=$proxied_msg_lines[$l]; 
		$NewDest =~ s/^Via:\s+SIP\s+//g;
		my ($IP, $Port) = Resolve_IP_or_rHOSTrDOMAIN ($NewDest);
		send_using_IP_and_port $IP, $Port, lines_to_sipmsg(@proxied_msg_lines);
	}
}


sub proxy_sip_method {
# Determine the Destination for this from the Method: line itself
# Proxy the message to that destination, INTACT.
#
	my @proxied_msg_lines=rev_filter_msg_lines $MYVIALINE_BASE, @_;

	my ($rHOSTrDOMAIN, $rHOST, $rDOMAIN, $sipURI, $Username) = parse_SIP_URI($proxied_msg_lines[0]);
	logit "info", "proxy_sip_method: to:$rHOSTrDOMAIN \n"; 
	dump_msg_lines "Proxied", @proxied_msg_lines;
	my ($IP, $Port) = Resolve_IP_or_rHOSTrDOMAIN($rHOSTrDOMAIN);
	send_using_IP_and_port $IP, $Port, lines_to_sipmsg(@proxied_msg_lines);
}

# ----------------------   S I P   M e t h o d   R e s p o n s e    ----------------------- #
sub INVITE_outbound {
	# 1. Resolv the domain lookup in the request_URI  [rURI] 
	#    which is rUSER@{rHOST.}rDOMAIN
	# 2. Insert MY via line and 
	# 3. Send on to new destination, determined as:
	#    o ip of rHOST.rDOMAIN, or
	#    o ip of SRV of rDOMAIN, or
	#    o ip of sip.rDOMAIN or else
	#    o turn the message around to sender with a NOT FOUND (404) method.
	# 4. Generate TRYING message and return to sender
	#     - or else
	#    Generate a 404 Not Found and return that.
	#

	# Trying Message
	$recv_sock->send(&lines_to_sipmsg(&generate_trying_msg_lines(@_)));   # Send back a TRYING message
##	$recv_sock->send(&lines_to_sipmsg(&generate_trying_msg_lines(@_)));   # Send back a TRYING message

	# Forward Message
	my ($forward_sipmsg, @forward_msg_lines);

	&generate_MyViaLine;
	@forward_msg_lines = &generate_forward_msg_lines(@_);

	@forward_msg_lines=generate_SOAP_msg_lines_if_regexp($REGEXP_INVITE_THIS_DOMAIN, @forward_msg_lines) if ($FLAG_SOAP);

	$forward_sipmsg = lines_to_sipmsg(@forward_msg_lines);
	my ($rHOSTrDOMAIN, $rHOST, $rDOMAIN, $sipURI, $Username) = parse_SIP_URI($_[0]);
	send_using_rHOSTrDOMAIN $rHOST, $rDOMAIN, $forward_sipmsg;
}

sub CANCEL_outbound {
	proxy_sip_method @_;
}
sub ACK_outbound {
	proxy_sip_method @_; # Just need to proxy this message - 
}
sub BYE_outbound {
	proxy_sip_method @_; # Just need to proxy this message - 
}
sub OK_outbound {
}
sub RING_outbound {
# Can't proxy this Ring or else the UA srews up.
}
sub TRYING_outbound {
}
sub REGISTER_outbound {
}
sub OPTIONS_outbound {
}
sub INFO_outbound {
}
sub PRACK_outbound {
}


# ---------------------------------    m a i n -------------------------------- #

sub main_message_loop {
	my $Method;

	$recv_sock = IO::Socket::INET->new(LocalPort => $MyPort, Proto =>'udp') 
		or die "$Me: Can NOT get socket: $@";

	logit "info", "\nWaiting for SIP messages on UDP port $MyPort \n\n";
	while ($recv_sock->recv($new_msg, $MAXLEN)) {
		my($port, $ipaddr) = sockaddr_in($recv_sock->peername);
		$hishost=gethostbyaddr($ipaddr, AF_INET);

		@new_msg_lines=split /\n/, $new_msg;  # Take the SIP message and split into array of lines
		chomp(@new_msg_lines);                # Remove the   \n off each line
		chop(@new_msg_lines);                 # Remove (any) \r off each line
##		@new_msg_lines= map  "=~ s/\r//g",   @new_msg_lines; # Remove (any) \r off each line
##		foreach (@new_msg_lines) {   "=~ s/\r//g",   @new_msg_lines; # Remove (any) \r off each line
##		@new_msg_lines= map  '$_ =~ s/\r//g',   @new_msg_lines; # Remove (any) \r off each line


		$Method=$new_msg_lines[0]; 
		logit "info",  sprintf("RECEIVED: From: $hishost ip:%s  port:$port \n", inet_ntoa($ipaddr));
		logit "info",  sprintf("RECEIVED: THE UA METHOD is +++%s+++ \n", $Method);
		&dump_msg_lines("Received", @new_msg_lines);
		@new_msg_lines=UNSOAP_msg_lines(@new_msg_lines) if ($FLAG_SOAP);
    # SIP METHODS
		   if ($new_msg_lines[0] =~ '^INVITE')   { INVITE_outbound    @new_msg_lines }
		elsif ($new_msg_lines[0] =~ '^CANCEL')   { CANCEL_outbound    @new_msg_lines }
		elsif ($new_msg_lines[0] =~ '^ACK')      { ACK_outbound       @new_msg_lines }
		elsif ($new_msg_lines[0] =~ '^BYE')      { BYE_outbound       @new_msg_lines }
		elsif ($new_msg_lines[0] =~ '^REGISTER') { REGISTER_outbound  @new_msg_lines }
		elsif ($new_msg_lines[0] =~ '^OPTIONS')  { OPTIONS_outbound   @new_msg_lines }
		elsif ($new_msg_lines[0] =~ '^INFO')     { INFO_outbound      @new_msg_lines }
		elsif ($new_msg_lines[0] =~ '^PRACK')    { PRACK_outbound     @new_msg_lines }
    # SIP Response Messages
		# 1xx Info              100 Trying       180 Ringing     181 Forwarded    
		#                       182 Queued    183 Progress
		# 2xx Success           200 OK 
		# 3xx Redir             300 MultiChoice  301 Moved Perm  302 Moved Temp   
		#                       305 Use Proxy 380 Altern Srv
		# 4xx Client Error      401 Unauthorised 402 Payment Req 403 Forbidden    404 Not Found 
		#                       405 Not Allowed     406 Not Accept     407 Proxy Auth Req
		#                       408 Timeout         409 Conflict       410 Gone
		#                       411 Length Requ     413 Too Large      414 URI too long
		#                       415 Unsupported media type
		#                       420 Bad Extention   421 Extension requ 480 Temp Unavailable
		#                       481 Call/Leg/Trans does not exist
		#                       482 Loop Detected   483 Too many Hops  484 Addr incomplete
		#                       485 Ambiguous       486 Busy Here      487 Requ Cancelled
		#                       488 Not Acceptable Here
		# 5xx Server Failure    500 Serv Internal Error       501 Not Implemented
		#                       502 Bad Gateway               503 Service Unavailable
		#                       504 G/W Timeout               505 Version Not Supported
		# 6xx Global Failure    600 Busy All Over             603 Decline
		#                       604 Does not exist ANYWHERE   606 Not Acceptable 
		#                        
		#                        
		# Specific SIP Response Handling
		#
##		elsif ($new_msg_lines[0] =~ '^SIP(\S+)\s200')     { OK_inbound             @new_msg_lines }
		elsif ($new_msg_lines[0] =~ '^SIP(\S+)\s180')     { RING_outbound          @new_msg_lines }
##		elsif ($new_msg_lines[0] =~ '^SIP(\S+)\s100')     { TRYING_outbound        @new_msg_lines }
		# General SIP Response Handling
		#
		elsif ($new_msg_lines[0] =~ '^SIP(\S+)\s(\S+)')   { proxy_sip_response_msg @new_msg_lines }
		else {
			logit "err", "RECEIVED: E R R O R:  Can not find Message TYPE for message:$new_msg_lines[0]\n";
		}
	}
	die "$Me:received: $!";
}



&configure;
logit "info", "+ ---+ ---+ ---+ ---+ ---+ ---+ ---+ ---+ ---+ ---+ ---+ ---+ ---+ ---+ ---+ ---+ ---+ ---+ ---+ ---+\n";
&dump_config;
&main_message_loop;



