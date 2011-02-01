-module(denes_proto).
-author('baryluk@smp.if.uj.edu.pl').

-export([decode_packet/1]).
-export([write_ll/1]).
-export([compression_tests_/0]).

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

% Reads and verify label from DNS packet, and returns {ok, ReversedLabels, Rest}

read_labels(Bin, WholePacket) when is_binary(Bin), byte_size(Bin) >= 1 ->
	io:format("reading labels: ~p~n", [Bin]),
	{Labels, Rest} = read_labels(Bin, [], WholePacket),
	ok = verify_labels(Labels),
	{ok, Labels, Rest}.

read_labels(<<2#00:2, 0:6, Rest/binary>>, Acc, _WholePacket) ->
	{Acc, Rest};
% binary pattern matching magic
read_labels(<<2#00:2, Length:6, Label:Length/binary, Rest/binary>>, Acc, WholePacket) when 1 =< Length, Length =< 63  ->
	read_labels(Rest, [Label | Acc], WholePacket);
% manualy unpack and check length (it is equivalent to clause two lines above)
%read_label(<<Length:8, Rest/binary>>, Acc) when Length >= 1, Length =< 63  ->
%	<<Label:Length/binary, Rest2/binary>> = Rest,
%	read_label(Rest2, [Label | Acc]);
read_labels(<<2#11:2, Offset:14, Rest/binary>>, Acc, WholePacket) ->
	<<_Skip:Offset, RestOfWhole/binary>> = WholePacket,
	throw(suffix_compression_not_implemented_yet),
	read_labels(RestOfWhole, Acc, WholePacket);

% binary label, experimental, [RFC3364][RFC3363][RFC2673]
read_labels(<<2#01000001, _Rest/binary>>, _Acc, _WholePacket) ->
	throw(binary_label_not_implemented);
% Reserved for future expansion. [RFC2671]
read_labels(<<2#01111111, _Rest/binary>>, _Acc, _WholePacket) ->
	throw(extended_label_not_implemented);
% extended label, RFC2671
read_labels(<<2#01:2, _:6, _Rest/binary>>, _Acc, _WholePacket) ->
	throw(extended_label_not_implemented);
% unallocated
read_labels(<<2#10:2, _:6, _Rest/binary>>, _Acc, _WholePacket) ->
	throw(unsupported_label_scheme).


% Important TODO: One should be aware that if trunction flag is true, then packet is incomplete and can contain broken entries.
%  as truncation bondoary can happen in the middle of record, rdata, or label.


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
types(28) -> aaaa; % rfc3596, a update from rfc1886 (obsolated), and obsolates a6 (defined in obsolated rfc3226), and rfc3152, (and so also 2553, 2766, 2772, 2874 with respect to ip6.int -> ip6.arpa transition)
types(29) -> loc; % experimental, rfc 1876
types(30) -> nxt; % Next Domain - OBSOLETE, RFC3755, RFC2535
types(31) -> eid;     % Endpoint Identifier                         [Patton]
types(32) -> nimloc;  % Nimrod Locator                              [Patton]
types(33) -> srv; % rfc 2782, obsolates (experimental) rfc 2052 (major change is that underscores are used to prevent clashes)

%  Note: in rfc 1002, there is types(32) -> nb; types(33) -> nbstat; % NetBIOS general Name Service, and NODE STATUS

types(34) -> atma; % ATM Address                                 [ATMDOC]
types(35) -> naptr; % Naming Authority Pointer                    [RFC2915][RFC2168][RFC3403]
types(36) -> kx; % Key Exchanger                               [RFC2230]
types(38) -> a6; % A6 ,Experimental, RFC3226, RFC2874, obsolated by aaaa in rfc3596
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

read_rr(P, WholePacket) when is_binary(P), byte_size(P) >= 1+2+2+4+2 ->   % at least: 1 byte of length in name (.), 2 bytes for type, 2 bytes for class, 4 bytes for ttl, 2 bytes for rdlength
	{ok, Labels, Rest} = read_labels(P, WholePacket),
	<<Type0:16, Class0:16, TTL:32/unsigned, RDataLength:16, RData:RDataLength/binary, Rest2/binary>> = Rest,
	% according to errata id 2130, to the rfc 1035 from 2010-04-05, section 3.2.1 errornously uses signed TTL, with conflict with section 4.1.3
	RDataLength = byte_size(RData),
	Type = types(Type0),
	Class = classes(Class0),
	{RR, Rest3} = case {Class, Type} of
		{in, aaaa} ->
			{ok, AAAA} = read_in_aaaa(RData),
			{{Type, Class, TTL, AAAA}, Rest2};
		{_, cname} ->
			{ok, CName} = read_cname(RData, WholePacket),
			{{Type, Class, TTL, CName}, Rest2};
		{in, a} ->
			{ok, IP} = read_in_a(RData),
			{{Type, Class, TTL, IP}, Rest2};
		{_, ns} ->
			{ok, NSDName} = read_ns(RData, WholePacket),
			{{Type, Class, TTL, NSDName}, Rest2};
		{_, ptr} ->
			{ok, PTR} = read_ptr(RData, WholePacket),
			{{Type, Class, TTL, PTR}, Rest2};
		{_, mx} ->
			{ok, MX} = read_mx(RData, WholePacket),
			{{Type, Class, TTL, MX}, Rest2};
		{_, mb} ->
			{ok, MX} = read_mb(RData, WholePacket),
			{{Type, Class, TTL, MX}, Rest2};
		{_, soa} ->
			{ok, SOA} = read_soa(RData, WholePacket),
			{{Type, Class, TTL, SOA}, Rest2};
		{in, wks} ->
			{ok, WKS} = read_in_wks(RData),
			{{Type, Class, TTL, WKS}, Rest2};
		{_, hinfo} ->
			{ok, HInfo} = read_hinfo(RData),
			{{Type, Class, TTL, HInfo}, Rest2};
		{_, minfo} ->
			{ok, MInfo} = read_minfo(RData, WholePacket),
			{{Type, Class, TTL, MInfo}, Rest2};
		{_, null} ->
			{ok, NULL} = read_null(RData),
			{{Type, Class, TTL, NULL}, Rest2};
		{_, 'UNKNOWN'} ->
			{{{other, Type}, Class, TTL, {opaque, RData}}, Rest2}
	end,
	{ok, {Labels, RR}, Rest3}.


% read string

read_string(<<Length:8, String:Length/binary, Rest/binary>> = P) when is_binary(P) ->
	{ok, String, Rest}.

% RData parsing for multiple RR types

% General class

read_cname(P, WholePacket) ->
	{ok, CName, <<>>} = read_labels(P, WholePacket),
	{ok, CName}.

read_hinfo(P) ->
	% According to RFC 1010, CPU should be a set of uppser case letters, digits, and hyper or slash. At most 40 characers allowed.
	% Must start with letter and and with letter or digit.
	{ok, CPU, Rest} = read_string(P),
	% Same rules as for CPU
	{ok, OS, <<>>} = read_string(Rest),
	{ok, {CPU, OS}}.

% experimental
read_mb(P, WholePacket) ->
	{ok, MADName, <<>>} = read_labels(P, WholePacket),
	{ok, MADName}.

% obsolate. use mx. reject or convert them as mx with prio 0
read_md(P, WholePacket) ->
	{ok, MADName, <<>>} = read_labels(P, WholePacket),
	{ok, MADName}.

% obsolate. use mx, reject or convert them as mx with prio 10
read_mf(P, WholePacket) ->
	{ok, MADName, <<>>} = read_labels(P, WholePacket),
	{ok, MADName}.

% experimental
read_mg(P, WholePacket) ->
	{ok, MADName, <<>>} = read_labels(P, WholePacket),
	{ok, MADName}.

% experimental
read_minfo(P, WholePacket) ->
	{ok, ResponsibleMailbox, Rest} = read_labels(P, WholePacket),
	{ok, ErrorMailbox, <<>>} = read_labels(Rest, WholePacket),
	{ok, {ResponsibleMailbox, ErrorMailbox}}.

% experimental
read_mr(P, WholePacket) ->
	{ok, NewName, <<>>} = read_labels(P, WholePacket),
	{ok, NewName}.

read_mx(<<Preference:16, Rest/binary>> = _P, WholePacket) ->
	{ok, Exchange, <<>>} = read_labels(Rest, WholePacket),
	{ok, {Preference, Exchange}}.

read_null(P) when byte_size(P) >= 0, byte_size(P) =< 65535 ->
	{ok, P}.

read_ns(P, WholePacket) ->
	{ok, NSDName, <<>>} = read_labels(P, WholePacket),
	{ok, NSDName}.

read_ptr(P, WholePacket) ->
	{ok, PTRDName, <<>>} = read_labels(P, WholePacket),
	{ok, PTRDName}.

read_soa(P, WholePacket) ->
	{ok, MName, Rest1} = read_labels(P, WholePacket),
	{ok, ResponsibleMailboxName, Rest2} = read_labels(Rest1, WholePacket), % yes, it is mailbox, but reading using labels, as hostmaster is assumes
	<<Serial:32, Refresh:32, Retry:32, Expire:32, MinimumTTL:32>> = Rest2, % all times in seconds
	{ok, {MName, ResponsibleMailboxName, Serial, Refresh, Retry, Expire, MinimumTTL}}.

read_txt(P) when byte_size(P) >= 1 ->
	% TODO: verify that P contains only characters allowed (
	{ok, P}.

% IN specific records

% IPv4 address
read_in_a(<<A:8, B:8, C:8, D:8>>) ->
	{ok, {A,B,C,D}}.

read_in_wks(<<A:8, B:8, C:8, D:8, IPProtocol:8, Bitmap/binary>>) ->
	% IPv4 address
	% IPProtoclo, for example TCP (6) or UDP
	% Bitmap: true or false for each next port starting from 0, 1, 2, 3, ...
	% TODO: decode bitmap into list of integers
	{ok, {{A,B,C,D}, IPProtocol, Bitmap}}.


% IPv6 address - auxilary function to decompose 16 bits into 4x4 bits
aaaa_nibles(<<H1:4, L1:4, H2:4, L2:4>>) ->
	{H1, L1, H2, L2}.

% IPv6 address
% 128 bits decomposed into 8 groups each being 4-tuple with 4-bit numbers
read_in_aaaa(<<A:16, B:16, C:16, D:16, E:16, F:16, G:16, H:16>>) ->
	%{ok, {aaaa_nibles(A),aaaa_nibles(D),aaaa_nibles(C),aaaa_nibles(D),aaaa_nibles(E),aaaa_nibles(F),aaaa_nibles(G),aaaa_nibles(H)}}.
	{ok, {A, B, C, D, E, F, G, H}}.


% TODO: optional additional restrictions for IN-ADDR.ARPA, ip6.arpa and IP6.INT . domain
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
	authorativeRRs = [],              % list()
	additionalRRs = []                % list()
}).

read_message(WholePacket = <<ID:16,
               QueryResponse:1, Opcode:4, AuthorityAnswer:1, Truncation:1, RecursionDesired:1,
               RecursionAvailable:1, ZeroReserved1:1, ZeroReserved2:1, _ZeroReserved3:1, ResponseCode:4,
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

	{Queries, Rest4} = lists:foldl(fun(_I, {AccL, Rest1}) ->
			{ok, RQName, Rest2} = read_labels(Rest1, WholePacket),
			QName = rlabels_to_string(RQName),
			<<QType:16, QClass:16, Rest3/binary>> = Rest2,
			Query = {qclasses(QClass), qtypes(QType), QName},
			{[Query | AccL], Rest3}
		end, {[], Rest}, lists:seq(1, QuestionsCount)),

	% answer, authority, and additional sections all shere the same format
	% it is actually the format of read_rr !

	{Answers, Rest5} = lists:foldl(fun(_I, {AccL, Rest1}) ->
			{ok, Labels_And_RR, Rest2} = read_rr(Rest1, WholePacket),
			{[Labels_And_RR | AccL], Rest2}
		end, {[], Rest4}, lists:seq(1, AnswersCount)),

	{AuthorativeRRs, Rest6} = lists:foldl(fun(_I, {AccL, Rest1}) ->
			{ok, Labels_And_RR, Rest2} = read_rr(Rest1, WholePacket),
			{[Labels_And_RR | AccL], Rest2}
		end, {[], Rest5}, lists:seq(1, NameServersRRCount)),

	{AdditionalRRs, Rest7} = lists:foldl(fun(_I, {AccL, Rest1}) ->
			{ok, Labels_And_RR, Rest2} = read_rr(Rest1, WholePacket),
			{[Labels_And_RR | AccL], Rest2}
		end, {[], Rest6}, lists:seq(1, AdditionalRRCount)),

	<<>> = Rest7,

	#dns_msg{
		id=ID,
		qr=QueryResponse,opcode=Opcode,authority=AuthorityAnswer,truncation=Truncation,
		recursion_desired=RecursionDesired,recursion_available=RecursionAvailable,
		authentic_data=AuthenticData,checking_disabled=CheckingDisabled,
		response_code=ResponseCode,
		questions=Queries,
		answers=Answers,
		authorativeRRs=AuthorativeRRs,
		additionalRRs=AdditionalRRs
		}.


rlabels_to_string([]) ->
	<<".">>;
rlabels_to_string(RLabels) ->
	iolist_to_binary(rlabels_to_string(RLabels, [])).

rlabels_to_string([], Acc) ->
	Acc;
rlabels_to_string([Label | RestRLabels], Acc) ->
	rlabels_to_string(RestRLabels, [Label, $. | Acc]).


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


%% Compression routines

% "Lables" is a list of labels (dns name components), so ListOfLabels is list of lists of labels.

write_ll(ListOfLabels) ->
	write_ll(ListOfLabels, false).

write_ll(ListOfLabels, CompressionDisabled) ->
	{Result, _LastDict, _LastPosition} = lists:foldl(fun (Labels, {Acc, Dict, Position}) ->
		{M, NewDict, NewPosition} = write_ll(Labels, Dict, Position, CompressionDisabled),
		{[lists:reverse(M) | Acc], NewDict, NewPosition}
	end, {[], dict:new(), 0},  ListOfLabels),
	lists:reverse(Result).

% Returns binary (or list of binaries in reversed order) encoding RR labels,
% and NewCompressionDict.
%
% Taking into account suffix (label) compression using CompressionDict,
% and current position. Tries to compress message maxially by finding maximal match,
% using hash table of previous label suffixes.
write_ll(Labels, CompressionDict, CurrentPosition, CompressionDisabled) ->
	write_ll_next(Labels, CompressionDict, CompressionDict, CurrentPosition, [], CompressionDisabled).

% when processing particular labels list in given RR, we only use OldCompressionDict
% for lookup in previous RRs, for smaller and smaller suffixes,
% each suffix is also added to the NewCompressionDict,
% which will be used in NEXT RRs (but not this one)
% We do not need to add suffixes if we found a whole suffix in compression dict,
% becuase this means that previous RR added them all already,
% as he failed to find any and added them all on the way.
write_ll_next([], _OldCompressionDict, NewCompressionDict, CurrentPosition, Acc, CompressionDisabled) ->
	% root domain, it is better to write it explicitly than compress from 1 to 2 bytes!
	% we also do not add it to compression dictionary, as it is pointless.
	M = <<2#00:2, 0:6>>,
	{[M | Acc], NewCompressionDict, CurrentPosition+1};
write_ll_next(Labels, OldCompressionDict, NewCompressionDict, CurrentPosition, Acc, CompressionDisabled) ->
	R = case CompressionDisabled of
		false -> dict:find(Labels, OldCompressionDict);
		true -> error % just for testing, we will still put data into Dict, but will always fail on lookup
		% NOTE: do not disable compression for production use!
		% it will impact performance, and will make many requests too big to fit into UDP DNS message!
		% If you really want, you can do this.
		% Server will still be perform according to standards.
	end,
	case R of
		{ok, Offset} when Offset < 4096 ->
			M = <<2#11:2, Offset:14>>,   % 2 bytes: 2 bits of marker, and 14 of offset from the begining
			Acc1 = [M | Acc],
			{Acc1, NewCompressionDict, CurrentPosition+2};
		error ->
			[L_H | L_T] = Labels,
			P2 = byte_size(L_H),
			true = (1 =< P2),
			true = (P2 =< 63),
			% todo: verify that L_H do not contain unlegal characters
			% TODO: verify that Labels is smaller 255 or less, even under compression
			% (that is they are smaller than 255 BEFORE compression, so can be decompressed in constant size buffer)
			% if this is not true, then fail (do NOT try to find shorter suffix!).
			M = <<2#00:2, P2:6, L_H/binary>>,
			Acc1 = [M | Acc],
			NewNewCompressionDict = case CompressionDisabled of
				false -> dict:store(Labels, CurrentPosition, NewCompressionDict); % store whole suffix
				true -> NewCompressionDict
			end,
			NewPosition = CurrentPosition + 1 + P2, % compute new position
			write_ll_next(L_T, OldCompressionDict, NewNewCompressionDict, NewPosition, Acc1, CompressionDisabled)
	end.

% compression tests and debuging

compression_test1_(Labels) ->
	EncNoCompress = write_ll(Labels, true),
	EncCompress = write_ll(Labels, false),
	EncBinCompress = iolist_to_binary(EncCompress),
	EncBin2 = iolist_to_binary(EncNoCompress),
	S = EncCompress,
	io:format("~p~n~n~p (without compression) -> ~p (with compression) bytes~n~p~n~n~n", [Labels, byte_size(EncBin2), byte_size(EncBinCompress), S]),
	ok.

compression_tests_() ->
	F = fun(X) -> compression_test1_(X) end,
	F([ ]),
	F([ [] ]),
	F([ [], [] ]),
	F([ [<<"ala">>] ]),
	F([ [<<"ala">>], [] ]),
	F([ [<<"ala">>], [<<"ala">>] ]),
	F([ [<<"ala">>, <<"ala">>], [<<"ala">>] ]),
	F([ [<<"ala">>], [<<"ola">>, <<"ala">>] ]),
	F([ [<<"ola">>, <<"ala">>], [<<"ala">>] ]),
	F([ [<<"ala">>], [<<"ola">>, <<"ela">>] ]),
	F([ [<<"ala">>, <<"ela">>], [<<"ala">>] ]),
	F([ [<<"ala">>], [<<"ala">>, <<"ala">>] ]),

	F([ [<<"smp">>, <<"if">>, <<"uj">>, <<"edu">>, <<"pl">>] ]),
	F([ [<<"smp">>, <<"if">>, <<"uj">>, <<"edu">>, <<"pl">>], [<<"pl">>] ]),
	F([ [<<"smp">>, <<"if">>, <<"uj">>, <<"edu">>, <<"pl">>], [<<"tytus">>, <<"smp">>, <<"if">>, <<"uj">>, <<"edu">>, <<"pl">>] ]),
	F([ [<<"tytus">>, <<"smp">>, <<"if">>, <<"uj">>, <<"edu">>, <<"pl">>], [<<"romeo">>, <<"smp">>, <<"if">>, <<"uj">>, <<"edu">>, <<"pl">>] ]),
	F([ [<<"tytus">>, <<"smp">>, <<"if">>, <<"uj">>, <<"edu">>, <<"pl">>], [<<"smp">>, <<"if">>, <<"uj">>, <<"edu">>, <<"pl">>] ]),
	F([ [<<"tytus">>, <<"smp">>, <<"if">>, <<"uj">>, <<"edu">>, <<"pl">>], [<<"dirac">>, <<"if">>, <<"uj">>, <<"edu">>, <<"pl">>] ]),

	F([ [<<"smp">>, <<"if">>, <<"uj">>, <<"edu">>, <<"pl">>], [<<"www">>, <<"pw">>, <<"edu">>, <<"pl">>] ]),

	F([
		[<<"sredniczarny">>, <<"vpn">>, <<"smp">>, <<"if">>, <<"uj">>, <<"edu">>, <<"pl">>],
		[<<"tytus">>, <<"smp">>, <<"if">>, <<"uj">>, <<"edu">>, <<"pl">>],
		[<<"romeo">>, <<"smp">>, <<"if">>, <<"uj">>, <<"edu">>, <<"pl">>],
		[<<"noisy">>, <<"smp">>, <<"if">>, <<"uj">>, <<"edu">>, <<"pl">>],
		[<<"lavinia">>, <<"smp">>, <<"if">>, <<"uj">>, <<"edu">>, <<"pl">>],
		[<<"malyczarny">>, <<"vpn">>, <<"smp">>, <<"if">>, <<"uj">>, <<"edu">>, <<"pl">>],
		[<<"nerissa">>, <<"smp">>, <<"if">>, <<"uj">>, <<"edu">>, <<"pl">>],
		[<<"julia">>, <<"smp">>, <<"if">>, <<"uj">>, <<"edu">>, <<"pl">>]
	]),


	F([
	[<<"c">>, <<"0">>, <<"6">>, <<"e">>, <<"7">>, <<"4">>, <<"e">>, <<"f">>, <<"f">>, <<"f">>, <<"c">>, <<"8">>, <<"e">>, <<"1">>, <<"2">>, <<"0">>, <<"7">>, <<"2">>, <<"5">>, <<"0">>, <<"b">>, <<"0">>, <<"f">>, <<"1">>, <<"0">>, <<"7">>, <<"4">>, <<"0">>, <<"1">>, <<"0">>, <<"0">>, <<"2">>, <<"ip6">>, <<"arpa">>],
	[<<"1">>, <<"0">>, <<"0">>, <<"0">>, <<"0">>, <<"0">>, <<"0">>, <<"0">>, <<"0">>, <<"0">>, <<"0">>, <<"0">>, <<"0">>, <<"0">>, <<"0">>, <<"0">>, <<"7">>, <<"2">>, <<"5">>, <<"0">>, <<"b">>, <<"0">>, <<"f">>, <<"1">>, <<"0">>, <<"7">>, <<"4">>, <<"0">>, <<"1">>, <<"0">>, <<"0">>, <<"2">>, <<"ip6">>, <<"arpa">>]
	]),

	F([
	[<<"0">>, <<"6">>, <<"0">>, <<"e">>, <<"a">>, <<"b">>, <<"e">>, <<"f">>, <<"f">>, <<"f">>, <<"f">>, <<"6">>, <<"6">>, <<"1">>, <<"2">>, <<"0">>, <<"0">>, <<"0">>, <<"0">>, <<"0">>, <<"0">>, <<"0">>, <<"0">>, <<"0">>, <<"0">>, <<"0">>, <<"0">>, <<"0">>, <<"0">>, <<"8">>, <<"e">>, <<"f">>, <<"ip6">>, <<"arpa">>],
	[<<"c">>, <<"0">>, <<"6">>, <<"e">>, <<"7">>, <<"4">>, <<"e">>, <<"f">>, <<"f">>, <<"f">>, <<"c">>, <<"8">>, <<"e">>, <<"1">>, <<"2">>, <<"0">>, <<"0">>, <<"0">>, <<"0">>, <<"0">>, <<"0">>, <<"0">>, <<"0">>, <<"0">>, <<"0">>, <<"0">>, <<"0">>, <<"0">>, <<"0">>, <<"8">>, <<"e">>, <<"f">>, <<"ip6">>, <<"arpa">>],
	[<<"c">>, <<"0">>, <<"6">>, <<"e">>, <<"7">>, <<"4">>, <<"e">>, <<"f">>, <<"f">>, <<"f">>, <<"c">>, <<"8">>, <<"e">>, <<"1">>, <<"2">>, <<"0">>, <<"7">>, <<"2">>, <<"5">>, <<"0">>, <<"b">>, <<"0">>, <<"f">>, <<"1">>, <<"0">>, <<"7">>, <<"4">>, <<"0">>, <<"1">>, <<"0">>, <<"0">>, <<"2">>, <<"ip6">>, <<"arpa">>],
	[<<"1">>, <<"0">>, <<"0">>, <<"0">>, <<"0">>, <<"0">>, <<"0">>, <<"0">>, <<"0">>, <<"0">>, <<"0">>, <<"0">>, <<"0">>, <<"0">>, <<"0">>, <<"0">>, <<"7">>, <<"2">>, <<"5">>, <<"0">>, <<"b">>, <<"0">>, <<"f">>, <<"1">>, <<"0">>, <<"7">>, <<"4">>, <<"0">>, <<"1">>, <<"0">>, <<"0">>, <<"2">>, <<"ip6">>, <<"arpa">>],
	[<<"2">>, <<"0">>, <<"0">>, <<"0">>, <<"0">>, <<"0">>, <<"0">>, <<"0">>, <<"0">>, <<"0">>, <<"0">>, <<"0">>, <<"0">>, <<"0">>, <<"0">>, <<"0">>, <<"7">>, <<"2">>, <<"5">>, <<"0">>, <<"b">>, <<"0">>, <<"f">>, <<"1">>, <<"0">>, <<"7">>, <<"4">>, <<"0">>, <<"1">>, <<"0">>, <<"0">>, <<"2">>, <<"ip6">>, <<"arpa">>]
	]),

	ok.

