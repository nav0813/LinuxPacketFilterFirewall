To build the LKM, which is the core packet-filtering module
 


make


--------------------------------------------------------------------
To clean and build

make clean
make 


--------------------------------------------------------------------
Load the module 

insmod firewall.ko


--------------------------------------------------------------------
Remove the 

module

rmmod firewall.ko
--------------------------------------------------------------------
To view the logs from the module

dmesg | grep "firewall"
--------------------------------------------------------------------

NOTE: Super user privileges are required to build and insert the module

--------------------------------------------------------------------
