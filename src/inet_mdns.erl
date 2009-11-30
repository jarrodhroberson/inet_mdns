-module(inet_mdns).

-include("inet_mdns.hrl").

-export([open/2,start/0]).
-export([stop/1,receiver/1]).

open(Addr,Port) ->
   {ok,S} = gen_udp:open(Port,[{reuseaddr,true},{ip,Addr},{multicast_ttl,4},{broadcast,true}, binary]),
   inet:setopts(S,[{add_membership,{Addr,{0,0,0,0}}}]),
   S.

close(S) -> gen_udp:close(S).

start() ->
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
process_dnsrec1(Sub,[Response|Rest]) ->
  Dom = Response#dns_rr.domain,
  case dict:is_key(Dom,Sub) of
	  true ->
		  NewSub = dict:append(Dom, Response, dict:new()),
		  {ok,Value} = dict:find(Dom, NewSub),
          io:format("~p=~p~n",[Dom,Value]);
     false ->
          %% do nothing for non-subscribed domains
         ok
  end,
  process_dnsrec1(Sub,Rest).
		
		   
