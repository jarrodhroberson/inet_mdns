-record(dns_header, 
	{
	 id = 0,       %% ushort query identification number 
	 %% byte F0
	 qr = 0,       %% :1   response flag
	 opcode = 0,   %% :4   purpose of message
	 aa = 0,       %% :1   authoritive answer
	 tc = 0,       %% :1   truncated message
	 rd = 0,       %% :1   recursion desired 
	 %% byte F1
	 ra = 0,       %% :1   recursion available
	 pr = 0,       %% :1   primary server required (non standard)
	               %% :2   unused bits
	 rcode = 0     %% :4   response code
	}).

-record(dns_rec,
	{
	 header,       %% dns_header record
	 qdlist = [],  %% list of question entries
	 anlist = [],  %% list of answer entries
	 nslist = [],  %% list of authority entries
	 arlist = []   %% list of resource entries
	}).

-record(dns_query,
	{
	 domain,       %% query domain
	 type,         %% query type
	 class         %% query class
	 }).

-record(dns_rr,
	{
	 domain = "",   %% resource domain
	 type = any,    %% resource type
	 class = in,    %% reource class
	 cnt = 0,       %% access count
	 ttl = 0,       %% time to live
	 data = [],     %% raw data
	 tm,            %% creation time
     bm = [],       %% Bitmap storing domain character case information.
     func = false   %% Optional function calculating the data field.
	}).