-module(zeroconf).

-include("zeroconf.hrl").

-export([open/2,start/0]).
-export([stop/1,receiver/1]).
-export([send/1]).
-export([sub/1,unsub/1,issub/1,subscriptions/1]).

send(Domain) ->
	{ok,S} = gen_udp:open(0,[{broadcast,true}]),
	P = #dns_rec{header=#dns_header{},qdlist=[#dns_query{domain=Domain,type=ptr,class=in}]},
	gen_udp:send(S,{224,0,0,251},5353,inet_dns:encode(P)),
	gen_udp:close(S).

open(Addr,Port) ->
   {ok,S} = gen_udp:open(Port,[{reuseaddr,true},{ip,Addr},{multicast_ttl,4},{broadcast,true}, binary]),
   inet:setopts(S,[{add_membership,{Addr,{0,0,0,0}}}]),
   S.

close(S) -> gen_udp:close(S).

start() ->
   register(mdns_subscriber,spawn(?MODULE,subscriptions,[dict:new()])),
   S=open({224,0,0,251},5353),
   Pid=spawn(?MODULE,receiver,[dict:store("_see._tcp.local",[],dict:new())]),
   gen_udp:controlling_process(S,Pid),
   {S,Pid}.

stop({S,Pid}) ->
   close(S),
   Pid ! stop.

receiver(Sub) ->
  receive
      {udp, _Socket, _IP, _InPortNo, Packet} ->
          process_dnsrec(Sub,inet_dns:decode(Packet)),
          receiver(Sub);
       stop -> 
		   true;
       AnythingElse -> 
		   io:format("RECEIVED: ~p~n",[AnythingElse]),
           receiver(Sub)
   end.

process_dnsrec(_Sub,{error,E}) -> io:format("Error: ~p~n", [E]);
process_dnsrec(Sub,{ok,#dns_rec{anlist=Responses}}) -> process_dnsrec1(Sub,Responses).

process_dnsrec1(_,[]) -> ok;
process_dnsrec1(Sub,[#dns_rr{domain=Dom}|Rest]) ->
  case dict:find(Dom,Sub) of
	  {ok,Result} ->
          io:format("Interesting domain ~p=~p~n",[Dom,Result]);
     error ->
          %% do nothing for non-interesting domains
         ok
  end,
  process_dnsrec1(Sub,Rest).

sub(E) ->
	mdns_subscriber ! {sub,E},
	ok.

unsub(E) ->
	mdns_subscriber ! {unsub,E},
	ok.

issub(E) ->
   mdns_subscriber ! {issub,E,self()},
   receive
       { _E, R } ->
           R
   end.

subscriptions(D) ->
	receive
		{sub,E} ->
			ND = dict:store(E,[],D),
			subscriptions(ND);
		{unsub,E} ->
			ND = dict:erase(E,D),
			subscriptions(ND);
		{issub,E,Pid} ->
			Pid ! {E,dict:is_key(E,D)},
			subscriptions(D);
		AnythingElse ->
			io:format("Unknown message ~p~n",[AnythingElse]),
			subscriptions(D)
	end.
		
		   
