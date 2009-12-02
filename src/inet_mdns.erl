-module(inet_mdns).

-include_lib("kernel/src/inet_dns.hrl").

-export([open/2,start/0]).
-export([stop/1,receiver/1]).
-export([subscribe/2,unsubscribe/2,getsubs/1]).

% gets a timestamp in ms from the epoch 1970-01-01
get_timestamp() ->
    {Mega,Sec,Micro} = erlang:now(),
    (Mega*1000000+Sec)*1000000+Micro.

open(Addr,Port) ->
   {ok,S} = gen_udp:open(Port,[{reuseaddr,true},{ip,Addr},{multicast_ttl,4},{broadcast,true}, binary]),
   inet:setopts(S,[{add_membership,{Addr,{0,0,0,0}}}]),
   S.

close(S) -> gen_udp:close(S).

start() ->
   S=open({224,0,0,251},5353),
   Pid=spawn(?MODULE,receiver,[dict:new()]),
   gen_udp:controlling_process(S,Pid),
   {S,Pid}.

stop({S,Pid}) ->
   close(S),
   Pid ! stop.

subscribe(Domain,Pid) ->
    Pid ! {sub,Domain}.

unsubscribe(Domain,Pid) ->
    Pid ! {unsub,Domain}.

getsubs(Pid) ->
    Pid ! {getsubs,self()},
    receive
        {ok,Sub} ->
            {ok,Sub}
    end.

receiver(Sub) ->
  receive
      {udp, _Socket, _IP, _InPortNo, Packet} ->
          NewSub = process_dnsrec(Sub,inet_dns:decode(Packet)),
          receiver(NewSub);
      {sub,Domain} ->
          receiver(dict:store(Domain,dict:new(),Sub));
      {unsub,Domain} ->
          receiver(dict:erase(Domain, Sub));
      {getsubs,Pid} ->
          Pid ! {ok,Sub},
          receiver(Sub);
      stop -> 
		   true;
       AnythingElse -> 
		   io:format("RECEIVED: ~p~n",[AnythingElse]),
           receiver(Sub)
   end.

% process the dns resource records list
process_dnsrec(Sub,{error,E}) ->
    io:format("Error: ~p~n", [E]), % TODO: Improve error handling (log or such)
    Sub;
process_dnsrec(Sub,{ok,#dns_rec{anlist=Responses}}) ->
    dict:map(fun(S, V) -> process_responses(S, V, Responses) end, Sub).
 
% process the list of resource records one at a time
process_responses(S, Value, Responses) ->
    lists:foldl(fun(#dns_rr{domain = Domain} = Response, Val) ->
        process_response(lists:suffix(S, Domain), Response, Val)
    end, Value, Responses).
 
process_response(false, _Response, Val) -> Val;
process_response(true, #dns_rr{ttl = TTL} = Response, Val) when TTL == 0 ->
    dict:new();
process_response(true, #dns_rr{domain = Domain, type = Type, class = Class} = Response, Val) ->
    NewRR = Response#dns_rr{tm=get_timestamp()},
    dict:store({Domain, Type, Class}, NewRR, Val).

