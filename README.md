### This project is a 2-part program. See [Part 1](https://github.com/mahdafr/20u_cs5391-t5) and [Part 2, this project](https://github.com/mahdafr/20u_cs5391-t6) for complete information.

# Assignment #6
In this task, you will be extending your part-3 code to _implement an actual level-3 router_ out of the ___cores21___ switch.
Copy the ___`part3controller.py`___ file to ___`part4controller.py`___, there is no new skeleton.
For the topology, you are given with the file (___`part4.py`___). The difference between ___`part3.py`___ and ___`part4.py`___ topologies is that the default route 'h10- eth0' was changed to "via 10.0.1.1" where "10.0.1.1" is the IP address of the gateway (i.e. router) for that particular subnet.
This effectively changes the network from a switched network (with hosts sending to a MAC address) into a routed network (hosts sending to an IP address).
Your part3controller should not work on this new topology!

To complete the assignment ___cores21___ will need to:
1. Handle ARP traffic across subnets (without forwarding); and
2. Forward IP traffic across link domains (changing the ethernet header);

__Note__: This also must be done in a _learning_ fashion: you __may not install static routes on cores21 startup__.
Instead, your router must learn of IP address through the ARP messages sent (this type
of learning is normally done at the MAC layers, but there are a bunch of implementations of those
in mininet already) and install these routes into the router dynamically. Imagine this as an
alternative form of DHCP where hosts instead inform the router of their addresses. You may
handle each of the individual ARP packets in the controller (i.e., not with flow rules) for part 4.
The IP routers must be done with flow rules.
__The other switches (e.g., s1) do not need to be modified and can continue to flood traffic.__

__Deliverables__:
1. Your `part4controller.py` file
2. A screenshot of the ___pingall___ command. All nodes but ___hnotrust___ should be able to send and respond to pings. Note that some pings will fail as the router learns of routes. Please answer, why would that be the case?
3. A screenshot of the ___iperf hnotrust1 h10___ and ___iperf h10 serv1___ commands. ___hnotrust___ should not be able to transfer to ___serv1___, but should be able to transfer to other hosts.
4. A screenshot of the output of the ___dpctl dump-flows___ command. This should contain all of the rules you've inserted into your switches.

## Results, _output(s) and result(s) stored in `_deliverables\part4.zip`_
<details>
  <summary>The Learning Switch</summary>

  - There are two major divisions in the program behavior:
    1. if we get an ARP packet:
      - we do not forward this traffic
      - instead, we only learn the network flow (src -> dst, focusing on the ports)
    2. if we get an IPv4 packet:
      - we want to forward this traffic to the right place (the correct out_port and the same destination)
      - but we send to an IP address instead of the MAC address (like used in part3 from [Task 5](https://github.com/mahdafr/20u_cs5391-t5/pox/part3controller.py))
      - this means that we add rules to the flow table each time we get new destinations to 'learn' which ports we can use to reach which destinations
  
</details>

<details>
  <summary>References/Reources</summary>

  - The [POX Wiki](https://noxrepo.github.io/pox-doc/html/) on:
    - [learning switches](https://github.com/mininet/openflow-tutorial/wiki/Create-a-Learning-Switch#Controller_Choice_POX_Python)
    - the `l2learning.py` [source code](https://github.com/noxrepo/pox/blob/carp/pox/forwarding/l2_learning.py)
    - the `l3learning.py` [source code](https://github.com/noxrepo/pox/blob/carp/pox/forwarding/l3_learning.py)
    - the `packet` [documentation](https://noxrepo.github.io/pox-doc/html/#working-with-packets-pox-lib-packet)
  - Sources for understanding Learning Switches
    - This [YouTube Video](https://www.youtube.com/watch?v=5awRpqxABMY)
    - This [Coursera course](https://www.coursera.org/learn/sdn)
    - This [3rd-party tutorial](https://haryachyy.wordpress.com/2014/06/03/learning-pox-openflow-controller-imitating-l3/)
    
  
</details>
