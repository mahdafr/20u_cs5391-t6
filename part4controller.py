# Part 4 of UWCSE's Project 3
#
# based on Lab Final from UCSC's Networking Class
# which is based on of_tutorial by James McCauley

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr, IPAddr6, EthAddr
import pox.lib.packet as pkt

log = core.getLogger()

#statically allocate a routing table for hosts
#MACs used in only in part 4
IPS = {
  "h10" : ("10.0.1.10", '00:00:00:00:00:01'),
  "h20" : ("10.0.2.20", '00:00:00:00:00:02'),
  "h30" : ("10.0.3.30", '00:00:00:00:00:03'),
  "serv1" : ("10.0.4.10", '00:00:00:00:00:04'),
  "hnotrust" : ("172.16.10.100", '00:00:00:00:00:05'),
}

class Part4Controller (object):
  """
  A Connection object for that switch is passed to the __init__ function.
  """
  def __init__ (self, connection):
    print (connection.dpid)
    # Keep track of the connection to the switch so that we can
    # send it messages!
    self.connection = connection

    # This binds our PacketIn event listener
    connection.addListeners(self)
    #use the dpid to figure out what switch is being created
    if (connection.dpid == 1):
      self.s1_setup()
    elif (connection.dpid == 2):
      self.s2_setup()
    elif (connection.dpid == 3):
      self.s3_setup()
    elif (connection.dpid == 21):
      self.cores21_setup()
    elif (connection.dpid == 31):
      self.dcs31_setup()
    else:
      print ("UNKNOWN SWITCH")
      exit(1)

  def s1_setup(self):
    self._allow_all()

  def s2_setup(self):
    self._allow_all()

  def s3_setup(self):
    self._allow_all()

  def cores21_setup(self):
    # do not use any following rules -- instead, we use switch learning
    self._block()                               # still block comm.s w/hnotrust
    self.ip_table = dict()                      # map: IPs

  def dcs31_setup(self):
    self._allow_all()

  # flood all communications going to through the net, dropping the rest
  def _allow_all(self, act=of.ofp_action_output(port=of.OFPP_FLOOD)):
    self.connection.send(of.ofp_flow_mod(action=act,
                                         priority=2))     # flood to all ports
    # otherwise, iperfs will hang
    self.connection.send(of.ofp_flow_mod(priority=1))
  
  # block ICMP from hnotrust to anyone, and block all IP to serv1
  def _block(self, src=IPS['hnotrust'][0], dst=IPS['serv1'][0]):
    block_icmp = of.ofp_flow_mod(priority=20,
                                 match=of.ofp_match(dl_type=0x800,
                                                    nw_proto=pkt.ipv4.ICMP_PROTOCOL,
                                                    nw_src=src))
    self.connection.send(block_icmp)
    block_to_serv = of.ofp_flow_mod(priority=19,
                                 match=of.ofp_match(dl_type=0x800,
                                                    nw_src=src,
                                                    nw_dst=dst))
    self.connection.send(block_to_serv)
  
  # allow IP traffic as normal
  def _internal_to_external(self):
    host = {10: (IPS['h10'][0], 1),
            20: (IPS['h20'][0], 2),
            30: (IPS['h30'][0], 3),
            40: (IPS['serv1'][0], 4),
            50: (IPS['hnotrust'][0], 5)}
    
    for i in range(len(host)):
      h = host[(i+1)*10][0]
      p = host[(i+1)*10][1]
      self.connection.send(of.ofp_flow_mod(action=of.ofp_action_output(port=p),
                                           priority=5,
                                           match=of.ofp_match(dl_type=0x800,
                                                              nw_dst=h)))

  #used in part 4 to handle individual ARP packets
  #not needed for part 3 (USE RULES!)
  #causes the switch to output packet_in on out_port
  def resend_packet(self, packet_in, out_port):
    msg = of.ofp_packet_out()
    msg.data = packet_in
    action = of.ofp_action_output(port = out_port)
    msg.actions.append(action)
    self.connection.send(msg)

  def _handle_PacketIn (self, event):
    """
    Packets not handled by the router rules will be
    forwarded to this method to be handled by the controller
    """

    packet = event.parsed # This is the parsed packet data.
    if not packet.parsed:
      log.warning("Ignoring incomplete packet")
      return

    packet_in = event.ofp # The actual ofp_packet_in message.
    
    if self._is_arp(packet):
      self._learn_IP(packet)
    else:
      self._forward_to_switch(packet)
    
    print('Unhandled packet from '+str(self.connection.dpid)+':'+packet.dump())

  def _is_arp(self, p):
    return isinstance(p.next, pkt.ipv4.arp)

  def _is_ip(self, p):
    return isinstance(p.next, pkt.ipv4.ipv4)

  def _learn_IP(self, p):
    pass

  def _forward_to_switch(self, p):
    pass

def launch ():
  """
  Starts the component
  """
  def start_switch (event):
    log.debug("Controlling %s" % (event.connection,))
    Part4Controller(event.connection)
  core.openflow.addListenerByName("ConnectionUp", start_switch)
