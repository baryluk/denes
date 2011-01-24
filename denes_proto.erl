-module(denes_proto).

-export([decode_packet/1]).

% based on RFC 1035
% other documents are referenced when needed
% see also rfc 1138, rfc5395
% 

% Functions for parsing and creating dns packets

% Records:
% ANY
% A, AAAA, PTR, MX, NS, CNAME, SOA, CNAME
% WKS, HINFO, MINFO, TXT
% DNSKEY, DS, RRSIG, NSEC



% Obsolated types:
%   MD, MF   by MX
% Experimental
%   MB, MG, MR, NULL


% syntax: ab.cd.ef.gh.ij  
% each component, label, need to be: at least 1 character, begin with letter, end with letter or digit, and can contain letters, digits or hyphen.)
%  a-9.pl  valid
%  9b.pl  invalid   (in this implementation it is valid)
%  a_9.pl invalid
%  9.pl invalid   (in this implementation it is valid)
%  -a.pl invalid
%  a-.pl invalid
% each label must have beetwen 1 - 63 characters.  64 or more, or empty label is disallowed!
% whole name must be beetwen 1-255 characters.

% TTL is positive 32 bit integer of seconds

% UDP message size need to be 512 bytes or less. (here we optionally allow for bigger messages)
% 512 bytes not cunting IP or UDP headers.
% If more, then only first 512 bytes of message is sent, and trunction flag is set.

% in this implementation we allow numbers to begin label
% all other characters are disallowed
% comparission beetwen labels and names should be done case insensitive

% We do not use atoms here, becuase this can lead to out of memmory
% We can try performing to_existing_atom, but we will need fallback method


% Decode whole packet

decode_packet(P) when is_binary(P) ->
	read_message(P).


% Just transforms name to lowercase
% TODO: in future, it could also handle punnycoded Unicode names
normalize_name(Name) ->
	Name.

% Reads and verify label from DNS packet, and returns {ReversedLabels, Rest}

read_labels(Bin) when is_binary(Bin), byte_size(Bin) >= 1 ->
	io:format("reading labels: ~p~n", [Bin]),
	{Labels, Rest} = read_labels(Bin, []),
	ok = verify_labels(Labels),
	{ok, Labels, Rest}.

read_labels(<<0:8, Rest/binary>>, Acc) ->
	{Acc, Rest};
% binary pattern matching magic
read_labels(<<2#00:2, Length:6, Label:Length/binary, Rest/binary>>, Acc) when 1 =< Length, Length =< 63  ->
	read_labels(Rest, [Label | Acc]).
% manualy unpack and check length
%read_label(<<Length:8, Rest/binary>>, Acc) when Length >= 1, Length =< 63  ->
%	<<Label:Length/binary, Rest2/binary>> = Rest,
%	read_label(Rest2, [Label | Acc]).
read_labels(<<2#11:2, Offset:14, Rest/binary>>, Acc, WholePacket) ->
	<<_Skip:Offset, RestOfWhole/binary>> = WholePacket,
	throw(suffix_compression_not_implemented),
	read_labels(RestOfWhole, Acc, WholePacket).

% binary label, experimental, [RFC3364][RFC3363][RFC2673]
% read_labels(<<2#01000001, Rest/binary>>, Acc, WholePacket) ->
% Reserved for future expansion. [RFC2671]
% read_labels(<<2#01111111, Rest/binary>>, Acc, WholePacket) ->
% extended label, RFC2671
% read_labels(<<2#01:2, _:6, Rest/binary>>, Acc, WholePacket) ->
% unallocated
% read_labels(<<2#10:2, _:6, Rest/binary>>, Acc, WholePacket) ->


% Important TODO: One should be aware that if trunction flag is true, then packet is incomplete and can contain broken entries.


% from rfc 1035
% Pointers can only be used for occurances of a domain name where the
% format is not class specific.  If this were not the case, a name server
% or resolver would be required to know the format of all RRs it handled.
%
% If a domain name is contained in a part of the message subject to a
% length field (such as the RDATA section of an RR), and compression is
% used, the length of the compressed name is used in the length
% calculation, rather than the length of the expanded name.
%

% This means that limits of 63 and 255 should be checked after decompression, which we actually perform.
% But to prevent cycles and very big domain names one should perform checking on the fly
% 1. This can be done in three ways. Limit recursion to say 1000.
% 2. Build list of all used pointers in given label construction, if at any point we are going to use pointer which is already in list stop processing, as we entered cycle.
% 3. Pointer are only allowed to the offset BEFOR current position. (this do not prevent cycles, but should be respected).
% 4. Essentially so one can have index of already current label start, and when performing pointer dereference use truncated packet,
%    or never go beyond last pointer jump origin.

verify_labels(Labels) ->
	verify_labels(Labels, 0).

verify_labels([],Sum) when Sum =< 255 ->
	ok;
verify_labels([Label | Rest], Sum) when is_binary(Label), 1 =< byte_size(Label), byte_size(Label) =< 63, byte_size(Label)+1+Sum =< 255 ->
	ok = verify_label(Label),
	verify_labels(Rest, byte_size(Label)+1+Sum).

verify_label(Label) when is_binary(Label), 1 =< byte_size(Label), byte_size(Label) =< 63 ->
	verify_label(Label, 0).


verify_label(<<>>, N) when 1 =< N, N =< 63 ->
	ok;
verify_label(<<FirstCharacter:8, Rest/binary>>, 0)
	when $a =< FirstCharacter, FirstCharacter =< $z;
	     $A =< FirstCharacter, FirstCharacter =< $Z;
	     $0 =< FirstCharacter, FirstCharacter =< $9 -> 
	verify_label(Rest, 1);
verify_label(<<Character:8, Rest/binary>>, N)
	when $a =< Character, Character =< $z;
	     $A =< Character, Character =< $Z;
	     Character =:= $-;
	     $0 =< Character, Character =< $9 -> 
	verify_label(Rest, N+1).

% Note: for SRV records labels can begin with underscode. for example:  _ldap._tcp.example.com

% todo: perform normalization when verifing


% Types and classes of records and queries

% based on rfc1035 and updates. whole list at http://www.iana.org/assignments/dns-parameters


% types(0) -> special usages,, see , [RFC2931], [RFC4034], [RFC5395][RFC1035], and http://www.iana.org/assignments/dns-parameters

types(1) -> a;
types(2) -> ns;
types(3) -> md;
types(4) -> mf;
types(5) -> cname;
types(6) -> soa;
types(7) -> mb;
types(8) -> mg;
types(9) -> mr;
types(10) -> null;
types(11) -> wks;
types(12) -> ptr;
types(13) -> hinfo;
types(14) -> minfo;
types(15) -> mx;
types(16) -> txt;
types(17) -> rp; % responsible person, rfc 1183
types(18) -> afsdb; % AFS DB, rfc 1183  % deprecated in rfc5864, one should use general SRV records, and follow rfc 5864 compatibility suggestions
types(19) -> x25; % experimental, rfc 1183
types(20) -> isdn; % experimental, rfc 1183
types(21) -> rt; % Route Throught,  experimental, rfc 1183
types(22) -> nsap; % [RFC1706]
types(23) -> 'nsap-ptr'; % [RFC1348]
types(24) -> sig; % for security signature                      [RFC4034][RFC3755][RFC2535]
types(25) -> key; % for security key                            [RFC4034][RFC3755][RFC2535]
types(26) -> px; %  X.400 mail mapping information              [RFC2163]
types(27) -> gpos; % rfc1712
types(28) -> aaaa; % rfc3596
types(29) -> loc; % experimental, rfc 1876
types(30) -> nxt; % Next Domain - OBSOLETE, RFC3755, RFC2535
types(31) -> eid;     % Endpoint Identifier                         [Patton]
types(32) -> nimloc;  % Nimrod Locator                              [Patton]
types(33) -> srv; % rfc 2782, obsolates (experimental) rfc 2052 (major change is that underscores are used to prevent clashes)

%  Note: in rfc 1002, there is types(32) -> nb; types(33) -> nbstat; % NetBIOS general Name Service, and NODE STATUS

types(34) -> atma; % ATM Address                                 [ATMDOC]
types(35) -> naptr; % Naming Authority Pointer                    [RFC2915][RFC2168][RFC3403]
types(36) -> kx; % Key Exchanger                               [RFC2230]
types(38) -> a6; % A6 ,Experimental, RFC3226, RFC2874
types(39) -> dname; % RFC2672
types(44) -> sshfp; % SSH Key Fingerprint                         [RFC4255];
types(45) -> ipseckey; % IPSECKEY                                    [RFC4025]
types(46) -> rrsig;
types(47) -> nsec;
types(48) -> dnskey;
types(49) -> dhcid;
types(50) -> nsec3;
types(51) -> nsec3param;
% 52-54 unasiggned
types(55) -> hip; % Host Identity Protocol                      [RFC5205]
types(56) -> ninfo;
types(57) -> rkey;
types(58) -> talink; % Trust Anchor LINK                           [Wijngaards]
% 59-98 unasiggned
types(99) -> spf;
types(100) -> uinfo;
types(101) -> uid;
types(102) -> gid;
types(103) -> unspec.


% only appropriate in queries
qtypes(249) -> tkey; %  Transaction Key, rfc2930
qtypes(250) -> tsig; % Transaction Signature, rfc2845
qtypes(251) -> ixfr; % incremental transfer, rfc1995
qtypes(252) ->
	axfr;
qtypes(253) ->
	mailb;
qtypes(254) ->
	maila;
qtypes(255) ->
	any;
qtypes(T) ->
	types(T).

% types(32768) -> ta; % trust authority, Weiler
% types(32769) -> dlv;  DNSSEC Lookaside Validation, RFC4431
% types(65280-65534) -> private_type;

classes(1) ->
	in;   % Internet
classes(2) ->
	cs;   % CSNET (obsolte)
classes(3) ->
	ch;   % Chaoss
classes(4) ->
	hs.   % Hesiod

% for queries
qclasses(255) ->
	any_class;
qclasses(254) ->
	none_class; % rfc 2136
qclasses(T) ->
	classes(T).


% Read RR

read_rr(P) when is_binary(P), byte_size(P) >= 1+2+2+4+2 ->   % at least: 1 byte of length in name (.), 2 bytes for type, 2 bytes for class, 4 bytes for ttl, 2 bytes for rdlength
	{ok, Labels, Rest} = read_labels(P),
	<<Type:16, Class:16, TTL:32/unsigned, RDataLength:16, RData:RDataLength/binary, Rest2/binary>> = Rest,
	% according to errata 2130, to the rfc 1035 from 2010-04-05, section 3.2.1 errornously uses signed TTL, with conflict with section 4.1.3
	RDataLength = byte_size(RData),
	case types(Type) of
		cname ->
			{ok, CName} = read_cname(RData),
			{{Type, Class, TTL, CName}, Rest2};
		ns ->
			{ok, NSDName} = read_ns(RData),
			{{Type, Class, TTL, NSDName}, Rest2};
		ptr ->
			{ok, PTR} = read_ptr(RData),
			{{Type, Class, TTL, PTR}, Rest2};
		mx ->
			{ok, MX} = read_mx(RData),
			{{Type, Class, TTL, MX}, Rest2};
		hinfo ->
			{ok, HInfo} = read_hinfo(RData),
			{{Type, Class, TTL, HInfo}, Rest2};
		a ->
			case classes(Class) of
				in ->
					{ok, IP} = read_in_a(RData),
					{{Type, Class, TTL, IP}, Rest2}
			end
	end.


% 
read_string(<<Length:8, String:Length/binary, Rest/binary>> = P) when is_binary(P) ->
	{ok, String, Rest}.

% RData parsing

% General class

read_cname(P) ->
	{ok, CName, <<>>} = read_labels(P).

read_hinfo(P) ->
	% According to RFC 1010, CPU should be a set of uppser case letters, digits, and hyper or slash. At most 40 characers allowed.
	% Must start with letter and and with letter or digit.
	{ok, CPU, Rest} = read_string(P),
	% Same rules as for CPU
	{ok, OS, <<>>} = read_string(Rest),
	{ok, {CPU, OS}}.

% experimental
read_mb(P) ->
	{ok, MADName, <<>>} = read_labels(P),
	{ok, MADName}.

% obsolate. use mx. reject or convert them as mx with prio 0
read_md(P) ->
	{ok, MADName, <<>>} = read_labels(P),
	{ok, MADName}.

% obsolate. use mx, reject or convert them as mx with prio 10
read_mf(P) ->
	{ok, MADName, <<>>} = read_labels(P),
	{ok, MADName}.

% experimental
read_mg(P) ->
	{ok, MADName, <<>>} = read_labels(P),
	{ok, MADName}.

% experimental
read_minfo(P) ->
	{ok, ResponsibleMailbox, Rest} = read_labels(P),
	{ok, ErrorMailbox, <<>>} = read_labels(Rest),
	{ok, {ResponsibleMailbox, ErrorMailbox}}.

% experimental
read_mr(P) ->
	{ok, NewName, <<>>} = read_labels(P),
	{ok, NewName}.

read_mx(<<Preference:16, Rest/binary>> = P) ->
	{ok, Exchange, <<>>} = read_labels(Rest),
	{ok, {Preference, Exchange}}.

read_null(P) when byte_size(P) >= 0, byte_size(P) =< 65535 ->
	{ok, P}.

read_ns(P) ->
	{ok, NSDName, <<>>} = read_labels(P),
	{ok, NSDName}.

read_ptr(P) ->
	{ok, PTRDName, <<>>} = read_labels(P),
	{ok, PTRDName}.

read_soa(P) ->
	{ok, MName, Rest1} = read_labels(P),
	{ok, ResponsibleMailboxName, Rest2} = read_labels(Rest1), % yes, it is mailbox, but reading using labels, as hostmaster is assumes
	<<Serial:32, Refresh:32, Retry:32, Expire:32, MinimumTTL:32>> = Rest2, % all times in seconds
	{ok, {MName, ResponsibleMailboxName, Serial, Refresh, Retry, Expire, MinimumTTL}}.

read_txt(P) when byte_size(P) >= 1 ->
	% TODO: verify that P contains only characters allowed (
	{ok, P}.

% IN specific records

read_in_a(<<A:8, B:8, C:8, D:8>>) ->
	{ok, {A,B,C,D}}.  % IPv4 address

read_in_wks(<<A:8, B:8, C:8, D:8, IPProtocol:8, Bitmap/binary>>) ->
	% IPv4 address
	% IPProtoclo, for example TCP (6) or UDP
	% Bitmap: true or false for each next port starting from 0, 1, 2, 3, ...
	{ok, {{A,B,C,D}, IPProtocol, Bitmap}}.


% Additional restrictions for IN-ADDR.ARPA. domain
%   - only SOA, NS and PTR or ANY (both in requests, domain file, or replay from us or other servers)

% parsed DNS message
-record(dns_msg, {
	id = throw(not_initalized),      % integer()
	qr = throw(not_initalized),      % bool()
	opcode = throw(not_initalized),  % integer()
	authority = 0,                   % bool()
	truncation = 0,                  % bool()
	recursion_desired = 0,           % bool()
	recursion_available = 0,         % bool()
	authentic_data = 0,              % bool(), should be cleared on response if not supported
	checking_disabled = 0,            % bool(), should be cleared on response if not supported
	response_code = throw(not_initalized), % integer()
	questions = [],                  % list()
	answers = [],                    % list()
	nameserversRR = [],              % list()
	additionalRR = []                % list()
}).

read_message(<<ID:16,
               QueryResponse:1, Opcode:4, AuthorityAnswer:1, Truncation:1, RecursionDesired:1,
               RecursionAvailable:1, ZeroReserved1:1, ZeroReserved2:1, ZeroReserved3:1, ResponseCode:4,
               QuestionsCount:16,
               AnswersCount:16,
               NameServersRRCount:16, % in authority section
               AdditionalRRCount:16,
               Rest/binary>>) ->

% Opcode:
%    0 - standard query (QUERY), 1 - inverse query (IQUERY), 2 - server status (STATUS), 3-15 - reserved
%      It is sufficient that only 0 is supported, and for other query types response code 4 (not implemented) is returned.
%      anyway IQUERY is obsolated in obsolated rfc 3425
%    3 - not assigned
%    4 - notify, rfc 1996
%    5 - update, rfc 2136
%    6-15 not assigned
% Truncation:
%   message is truncated (to 512 bytes normally) becuase of response was bigger than 512, or MTU is less than response size
% RecursionAvailable cleared in response if recursion not available
% ZeroReserved:
%   should be zero in query and response (NOT COPY when responsing)
%   Take look at, RFC4035, for bit 10 and 11 usage, known as AD Authentic Data, CD Checking Disabled.
%   see also [RFC5395], 
    AuthenticData = ZeroReserved1,
    CheckingDisabled = ZeroReserved2,
% Server response codes:
%   rcodes(0) -> noerror; % no error,
%   rcodes(1) -> formerr; % format error (badly formated query),
%   rcodes(2) -> servfail; % server failure (problems),
%   rcodes(3) -> nxdomain; % name error (authorative dns sends this if domain name do not exists)
%   rcodes(4) -> notimp; % not implemented
%   rcodes(5) -> refused; % refused (for example recursion or zone transfer not allowed, or given name is not available for given client only)
%   rcodes(6) -> yxdomain; % Name Exists when it should not,  rfc 2136
%   rcodes(7) -> yxrrset; % RR Set Exists when it should not, rfc 2136
%   rcodes(8) -> nxrrset; % RR Set that should exist does not, rfc 2136
%   rcodes(9) -> notauth; % Server Not Authoritative for zone, rfc 2136
%   rcodes(10) -> notzone; % Name not contained in zone , rfc 2136
%   % rcodes(11-15 - not assigned
%   rcodes(16) -> badvers; % Bad OPT Version , rfc 2671
%   rcodes(16) -> badsig; % TSIG Signature Failure, rfc 2845
%   rcodes(17) -> badkey; % Key not recognized, rfc 2845
%   rcodes(18) -> badtime; % Signature out of time window, rfc 2845
%   rcodes(19) -> badmode; % Bad TKEY Mode, rfc 2930
%   rcodes(20) -> badname; % Duplicate key name, rfc 2930
%   rcodes(21) -> badalg; % Algorithm not supported, rfc 2930
%   rcodes(22) -> badtrunc. % Bad Truncation, rfc 4635
%   % 23-3840 - not assigned
%   % 3841-4095 - private
%   % 4096-65534 - not assigned
%   % 65535 - reserved.

	1 = QuestionsCount, % for testing

	{ok, QName, Rest2} = read_labels(Rest),
	<<QType:16, QClass:16, Rest3/binary>> = Rest2,
	Query = {qclasses(QClass), qtypes(QType), QName},

	Queries = [Query],

	% answer, authority, and additional sections all shere the same format
	% it is actually the format of read_rr !



	#dns_msg{id=ID,qr=QueryResponse,opcode=Opcode,authority=AuthorityAnswer,truncation=Truncation,
		recursion_desired=RecursionDesired,recursion_available=RecursionAvailable,
		authentic_data=AuthenticData,checking_disabled=CheckingDisabled,
		response_code=ResponseCode,
		questions=Queries}.


rlabels_to_string(RLabels) ->
	rlabels_to_string(RLabels, []).

rlabels_to_string([], Acc) ->
	[Acc | $. ];
rlabels_to_string([Label | RestRLabels], Acc) ->
	rlabels_to_string(RestRLabels, [Label | Acc]).


% One can use {packet,2} for reciving this messages also
read_message_tcp(<<Length:16, Rest:Length/binary>>) ->
	read_message(Rest).
	% normally client will close connection first,
	% do not close connection on our side, but send answers anyway, then close.


% if query contain qclass=any, or other multi-class query, then response should not be authorative, unless it is for sure than answwer covers all classes

% if in response, one want to add RR to additional RR section, but it is already in anwers or authority section, it can (and probably should) be omited.

% from rfc
% When a response is so long that truncation is required, the truncation
% should start at the end of the response and work forward in the
% datagram.  Thus if there is any data for the authority section, the
% answer section is guaranteed to be unique.

% so. if response is to large, server should not rearange records, but leave it in the same order,
% this make it possible for a client to uniqly determine answer,
% as well client can ommit restarting query over TCP if truncated part do not containt any data of interest to him.

% rfc 3597 (handling of unknownRRs)

% AS of compression., 
%   To avoid such corruption, servers MUST NOT compress domain names
%   embedded in the RDATA of types that are class-specific or not well-
%   known [this given in rfc 1035].
%
% This is becuase server should just copy transparently unknown RRs when transmiting, but problem is that
% given RRs can land in different place in new packet, so decompression will not work correctly.
% Becuase no server can know if any given RDATA section contains compression pointers, and in what format,
% they are disallowed in RDATA.
%
% There some speciall cases contraty to this: PX records in rfc2163, SIG, NXT records in rfc2535
% Both PX, SIG and NXT was subsequently updated or obsolated, and now MUST NOT use compression.
%
% When reciving:
%   Receiving servers MUST decompress domain names in RRs of well-known
%   type, and SHOULD also decompress RRs of type RP, AFSDB, RT, SIG, PX,
%   NXT, NAPTR, and SRV (although the current specification of the SRV RR
%   in [RFC2782] prohibits compression, [RFC2052] mandated it, and some
%   servers following that earlier specification are still in use).
%
% owner of RR can still can be compressed and decompressed. 
%
% Make sure to read also section 7 and  Errata ID: 1063 of rfc 3597
%
% Text representation.
%   Unknown classes should be written as CLASS12345
%   Unknown RR types as TYPE12345
%   RDATA of unknown RRs should written using generic binary format (see rfc 3597)
%
%