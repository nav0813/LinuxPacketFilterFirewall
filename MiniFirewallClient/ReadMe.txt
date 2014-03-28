To build
make -f Makefile_MiniFirewall
-------------------------------------
To clean and build

make -f Makefile_MiniFirewall clean
make -f Makefile_MiniFirewall
-------------------------------------
Set firewall policy

./MiniFirewall --in/--out --proto <ALL/TCP/UDP> --dstip <IP address> --dstpt <port number> 
--srcip <IP address> --srcpt <port number>--action <BLOCK/UNBLOCK>
-------------------------------------

Help

./MiniFirewall --help
-------------------------------------

NOTE: Super user privileges are required to write the firewall policy to the /proc filesystem

--------------------------------------------------------------------
