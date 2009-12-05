-module(inet_mdns).

-include_lib("kernel/src/inet_dns.hrl").

-export([start/0]).
-export([stop/1,receiver/1]).
-export([subscribe/2,unsubscribe/2,getsubs/1]).
-export([send/0]).

-define(ADDR,{224,0,0,251}).
-define(PORT,5353).

send() ->
    H = #dns_header{qr=1,aa=1},
    {ok,HN} = inet:gethostname(),
    D = "test@" ++ HN ++ "._test._tcp.local",
    R = #dns_rr{domain="_test._tcp.local",type=ptr,ttl=4500,data=D},
    Rec = #dns_rec{header=H,anlist=[R]},
    {ok,S}=gen_udp:open(0,[]),
    inet:setopts(S, [{reuseaddr,true},{broadcast,true}]),
    gen_udp:send(S,?ADDR,?PORT,inet_dns:encode(Rec)).

get_timestamp() ->
    %% gets a timestamp in ms from the epoch 1970-01-01
    {Mega,Sec,Micro} = erlang:now(),
    (Mega*1000000+Sec)*1000000+Micro.

start() ->
    %% start the process listening for mdns messages
   {ok,S} = gen_udp:open(?PORT,[{reuseaddr,true},{ip,?ADDR},binary]),
   inet:setopts(S,[{add_membership,{?ADDR,{0,0,0,0}}}]),
   Pid=spawn(?MODULE,receiver,[dict:new()]),
   gen_udp:controlling_process(S,Pid),
   {S,Pid}.

stop({S,Pid}) ->
   gen_udp:close(S),
   Pid ! stop.

subscribe(Domain,Pid) -> Pid ! {sub,Domain}.

unsubscribe(Domain,Pid) -> Pid ! {unsub,Domain}.

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

process_dnsrec(Sub,{error,E}) ->
    io:format("Error: ~p~n", [E]), % TODO: Improve error handling
    Sub;
process_dnsrec(Sub,{ok,#dns_rec{qdlist=Queries,anlist=Responses}}) ->
    process_queries(Queries),
    dict:map(fun(S,V) -> process_responses(S,V,Responses) end, Sub).
 
process_queries([]) -> ok;
process_queries(Queries) ->
    io:format("Queries: ~p~n",[Queries]),
    Reg = ["_see._tcp.local"],
    lists:foreach(fun(Q) -> case lists:member(Q#dns_query.domain,Reg) of 
                                true -> io:format("HIT: ~p~n",[Q]);
                                false -> io:format("MISS: ~p~n",[Q]) 
                            end 
                  end, Queries),
    lists:foreach(fun(Q) -> process_query(true,Q) end, Queries).
    %lists:foreach(fun(Q) -> process_query(lists:member(Q#dns_query.domain,Reg),Q) end, Queries).

process_query(false,_) -> ok;
process_query(true,Query) ->
    io:format("Registered Query: ~p~n",[Query]),
    H = #dns_header{qr=1,aa=1},
    D = "test@Blackintosh._test._tcp.local",
    R = #dns_rr{domain="_test._tcp.local",type=ptr,ttl=4500,data=D},
    Rec = #dns_rec{header=H,anlist=[R]},
    {ok,S} = gen_udp:open(5353,[{reuseaddr,true},{ip,{224,0,0,251}},{multicast_ttl,4},{broadcast,true}, binary]),
    gen_udp:send(S, {224,0,0,251}, 5353, inet_dns:encode(Rec)),
    gen_udp:close(S).

process_responses(S, Value, Responses) ->
    io:format("Responses ~p~n",[Responses]),
    lists:foldl(fun(#dns_rr{domain = Domain} = Response, Val) ->
        process_response(lists:suffix(S, Domain), Response, Val) end, Value, Responses).
 
process_response(false, _Response, Val) -> Val;
process_response(true, #dns_rr{ttl=TTL} = _Response, _Val) when TTL == 0 ->
    %% the server left and lets us know this because TTL == Zero
    dict:new();
process_response(true, #dns_rr{domain = Domain, type = Type, class = Class} = Response, Val) when Type == txt ->
    DTXT = lists:foldl(fun(T,D) -> {K,V} = normalize_kv(T),dict:store(K,V,D) end,dict:new(),Response#dns_rr.data),
    NewRR = Response#dns_rr{tm=get_timestamp(),data=DTXT},
    dict:store({Domain,Type,Class},NewRR,Val);
process_response(true, #dns_rr{domain = Domain, type = Type, class = Class} = Response, Val) ->
    NewRR = Response#dns_rr{tm=get_timestamp()},
    dict:store({Domain,Type,Class},NewRR,Val).

normalize_kv(T) ->
    %% normalize single boolean key value entries
    %% make "key" == "key=true"
    %% make "key=" == "key=[]"
    case re:split(T,"=",[{return,list}]) of 
        [K] -> {K,true}; 
        [K,V] -> {K,V} 
    end.












