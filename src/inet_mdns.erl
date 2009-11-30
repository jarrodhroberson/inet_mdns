-module(inet_mdns).

-include_lib("kernel/src/inet_dns.hrl").

-export([open/2,start/0]).
-export([stop/1,receiver/1]).

% gets a timestamp in ms from the epoch
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
   % TODO: this is just for testing, I am adding a subscription for iChat for testing 
   Pid=spawn(?MODULE,receiver,[dict:store("_presence._tcp.local",sets:new(),dict:new())]),
   gen_udp:controlling_process(S,Pid),
   {S,Pid}.

stop({S,Pid}) ->
   close(S),
   Pid ! stop.

receiver(Sub) ->
  receive
      {udp, _Socket, _IP, _InPortNo, Packet} ->
          DNSREC = inet_dns:decode(Packet),
          %io:format("******~n~p~n******~n",[DNSREC]),
          NewSub = process_dnsrec(Sub,DNSREC),
          receiver(NewSub);
      {sub,dump} ->
          io:format("~p~n",[Sub]),
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

% test to see if a dns_rr.domain is subscribed to
is_subscribed(_,[]) -> false;
is_subscribed(Dom,[S|Rest]) ->
    case lists:suffix(S,Dom) of
        true ->
            {ok,S};
        false ->
            is_subscribed(Dom,Rest)
    end.

% process the list of resource records one at a time
process_dnsrec1(Sub,[]) -> 
    io:format("Subscriptions: ~p~n",[Sub]),
    Sub;
process_dnsrec1(Sub,[Response|Rest]) ->
  Dom = Response#dns_rr.domain,
  case is_subscribed(Dom,dict:fetch_keys(Sub)) of
	  {ok,SD} ->
		  {ok,Value} = dict:find(SD,Sub),
          % update the dns_rr to the current timestamp 
          NewRR = Response#dns_rr{tm=get_timestamp()},
          NewValue = sets:add_element(NewRR,Value),
          NewSub = dict:store(SD,NewValue,Sub),
          io:format("Stored: ~p=~p~n",[Dom,NewSub]),
          process_dnsrec1(NewSub,Rest);
     false ->
          process_dnsrec1(Sub,Rest)
  end.
		
		   
