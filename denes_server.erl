-module(denes_server).
-author('baryluk@smp.if.uj.edu.pl').

-export([start/0, start/1, server/1, process/5]).

-define(PORT, 9953). % Do not change to 53! Use iptable rule to forward port 53 to 9953. Thanks.
-define(IP, {0,0,0,0}).
%-define(OtherOpts, [{write_concurrency, true}]).
-define(OtherOpts, []).

% NOTE: all below should be configurable

% TODO: listen on multiple interfaces, multiple ports, multiple addresses, and ipv6
% TODO: cache, and negative caching (caching of request which returned that given name+record do not exists)
% TODO: be sure to not poison cache
% TODO: do not cache bogus answers, or answers returned using TCP (larger than 512).
% TODO: recursive and non-recursive
% TODO: non-recursive modes: delegation, sending upstream (but with caching), forward&reverse zones
% TODO: dnssec
% TODO: queries randomization
% TODO: dns over TCP
% TODO: AXFR
% TODO: ACLs and matchers (ipv4, ipv6, subdomains, etc)
% TODO: blacklists for queries od domain and subdomains, or for returned IP
% TODO: views
% TODO: root servers and upstream server (per domain)
% TODO: memory, process and time limits
% TODO: load ballancing in multiple ways (for example when sending to upstream servers or root server be biased toward faster nodes)
% TODO: black and white lists - like used in MTA,
% TODO: loading data from simple txt files, erlang tuples, BIND files, Mnesia or Postgresql database
% TODO: Dynamic dns update
% TODO: wildcard dns records
% TODO: using local databases for example for blocking connections to the fishing and malwear sites, based on IP or Domain name
% TODO: blocking MX queries, and removing them from additional section
% TODO: Serialization of queries from single IP
% TODO: ratelimiting
% TODO: overload control
% TODO: Filtering out IPv6 or IPv4 addresses from answers (if both exists, and keeping only IPv4 or IPv6, or returning NXDOMAIN)
% TODO: reject DNS messages which uses private range of record types 65280-65534

start() ->
	start(?PORT).

start(Port) ->
	Pid = spawn(fun() -> server(Port) end),
	{ok, Pid}.

server(Port) ->
	Cache = ets:new(?MODULE, [public, set, named_table] ++ ?OtherOpts),
	{ok, Socket} = gen_udp:open(Port, [binary, {recbuf, 2048}, {reuseaddr, true}]),
	loop(0, Cache, Socket).

loop(I, Cache, Socket) ->
	receive
		{udp, Socket, Src_IP, Src_Port, Packet} ->
			spawn(?MODULE, process, [Cache, Socket, Src_IP, Src_Port, Packet]),
			loop(I+1, Cache, Socket);
		Other ->
			io:format("Other message ~p~n", [Other]),
			?MODULE:loop(I, Cache, Socket)
	end.

process(Cache, Socket, Src_IP, Src_Port, Packet) ->
	QR = denes_proto:decode_packet(Packet),
	io:format("Packet: ~p~n", [QR]),
	ok.
