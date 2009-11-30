-module(inet_mdns).

-include_lib("kernel/src/inet_dns.hrl").

-export([open/2,start/0]).
-export([stop/1,receiver/1]).

get_timestamp() ->
    {Mega,Sec,Micro} = erlang:now(),
    (Mega*1000000 + Sec)*1000000 + Micro.
    

open(Addr,Port) ->
   {ok,S} = gen_udp:open(Port,[{reuseaddr,true},{ip,Addr},{multicast_ttl,4},{broadcast,true}, binary]),
   inet:setopts(S,[{add_membership,{Addr,{0,0,0,0}}}]),
   S.

close(S) -> gen_udp:close(S).

start() ->
   S=open({224,0,0,251},5353),
   Pid=spawn(?MODULE,receiver,[dict:store("_presence._tcp.local",sets:new(),dict:new())]),
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

% process the dns resource records list
process_dnsrec(_Sub,{error,E}) -> 
    io:format("Error: ~p~n", [E]);
process_dnsrec(Sub,{ok,#dns_rec{anlist=Responses}}) -> 
    process_dnsrec1(Sub,Responses).

% process the list of resource records one at a time
process_dnsrec1(_,[]) -> ok;
process_dnsrec1(Sub,[Response|Rest]) ->
  Dom = Response#dns_rr.domain,
  case dict:is_key(Dom,Sub) of
	  true ->
		  {ok,Value} = dict:find(Dom,Sub),
          NewRR = Response#dns_rr{tm=get_timestamp()},
          NewValue = sets:add_element(NewRR,Value),
          NewSub = dict:store(Dom,NewValue,Sub),
          io:format("~p=~p~n",[Dom,NewValue]),
          process_dnsrec1(NewSub,Rest);
     false ->
          %% do nothing for non-subscribed domains
         ok
  end,
  process_dnsrec1(Sub,Rest).
		
		   
