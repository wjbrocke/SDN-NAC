from pox.core import core
import pox.openflow.libopenflow_01 as of
import pox.lib.packet as pkt
from pox.lib.packet.arp import arp
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.udp import udp
from pox.lib.packet.tcp import tcp 
from pox.lib.packet.ethernet import ethernet
from pox.lib.addresses import IPAddr, EthAddr
from pox.lib.util import dpidToStr, strToDPID
import threading
import MySQLdb
import xmlrpclib
import netaddr
from SimpleXMLRPCServer import SimpleXMLRPCServer


###################################################
# CONFIGURATION - update these values to match
# your environment as required.
###################################################
# dpid of the openflow switch in your environment
dpid = "00-01-e8-8b-95-24|1"

# openflow switch supports matching ARP messages
dp_supports_arp_match = False

# openflow switch supports matching IP addresses
dp_supports_l3_match = True

# network configuration
networks = {
    '10.0.0.0/24'  : {'untrusted' : 250, 'trusted' : 1250, 'portal' : 2250},
    '10.0.1.0/24' : {'untrusted' : 251, 'trusted' : 1251, 'portal' : 2251},
}

# the Router MAC address
router = EthAddr("00:1b:d4:70:7b:d8")
# the Portal MAC address (recommend that this be set to the Router MAC)
# note: this means you should CHANGE the MAC address on the portal interfaces
# note: facing clients via MACADDR="00:1b:d4:70:7b:d8", etc
portal = router
# ports on OpenFlow switch facing the client
# Note: If only a single port is used on OpenFlow switch (if capable)
# use of.OFPP_IN_PORT as the action
client_port_match = 2
client_port_action = 2
# number of seconds that authenticated clients can be idle before timing out their session
client_idle_timeout = 30
# ports on OpenFlow switch facing infrastructure (router,portal)
# Note: If only a single port is used on OpenFlow switch (if capable)
# use of.OFPP_IN_PORT as the action
router_port_match = 1
router_port_action = 1
portal_port_match = 1
portal_port_action = 1
#
# MySQL database connection parameters
db_host = "localhost"
db_user = "nac"
db_pass = "nacnacwh053dar3?"
db_name = "nac"
###################################################
log = core.getLogger()
db  = MySQLdb.connect(host=db_host, user=db_user, passwd=db_pass, db=db_name)
###################################################

def isManaged(ip):
    IP = netaddr.IPAddress(ip)
    for network,vlans in networks.iteritems():
        NET = netaddr.IPNetwork(network)
        if(NET.__contains__(IP)):
            return True
    return False

def getVLANs(ip):
    IP = netaddr.IPAddress(ip)
    for network,vlans in networks.iteritems():
        NET = netaddr.IPNetwork(network)
        if(NET.__contains__(IP)):
            return vlans
    return {}

def _handle_flowremoved (event):
   
    if event.idleTimeout:
        query = "UPDATE tbl_nac_session SET end_dt = now() WHERE end_dt IS NULL AND mac_address = '%s'" % (event.ofp.match.dl_src)
        cursor = db.cursor()
        cursor.execute(query)


def _handle_packetin (event):
    pass

def _handle_portstatus (event):
    if event.added:
        log.debug("Port %s on Switch %s has been added" % (event.port, event.dpid))

def getConnection():
    for con in core.openflow.connections:
        return con

def pClient(username,mac,ip=""):
    # permit traffic from the client to the router - i.e. auth successful
    connection = core.openflow.getConnection(strToDPID(dpid))
    MAC = EthAddr(mac)
    IP  = IPAddr(ip)
    vlan = getVLANs(ip)
    query = "INSERT into tbl_nac_session (username,mac_address,ip_address,start_dt) VALUES ('%s','%s','%s',now())" % (username,mac,ip)
    msg = None

    # note: if the openflow switch supports L3 matching in addition to L2 matching
    # note: matching on both will result in higher security - but not all support both.
    # note: if we match on L3 and ARP matching is not supported (see sPortal),
    # note: ARPs from the client will not flow to the router but rather to the portal
    # note: so it does not make sense to match on L3 unless we can also match on ARPs
    # note: but technically you could comment out "and dp_supports_arp_match" if you don't
    # note: care that ARPs from clients always go to your portal which runs proxy ARP
    if dp_supports_l3_match and dp_supports_arp_match:
        msg = of.ofp_flow_mod()
        msg.flags = of.OFPFF_SEND_FLOW_REM
        msg.idle_timeout = client_idle_timeout
        msg.priority = 32768
        msg.match.in_port = client_port_match
        msg.match.dl_src = MAC
        msg.match.dl_type = pkt.ethernet.IP_TYPE
        msg.match.nw_src = IP
        msg.actions.append(of.ofp_action_vlan_vid(vlan_vid = vlan['trusted']))
        msg.actions.append(of.ofp_action_output(port = router_port_action))
    else:
        msg = of.ofp_flow_mod()
        msg.flags = of.OFPFF_SEND_FLOW_REM
        msg.idle_timeout = client_idle_timeout
        msg.priority = 32768
        msg.match.dl_src = MAC
        msg.actions.append(of.ofp_action_vlan_vid(vlan_vid = vlan['trusted']))
        msg.actions.append(of.ofp_action_output(port = router_port_action))
    if msg:
        cursor = db.cursor()
        cursor.execute(query)
        connection.send(msg)


 

def sPortal(connection):
    for network,vlan in networks.iteritems():

        # permit DNS to flow from clients to router
        msg = of.ofp_flow_mod()
        msg.priority = 20
        msg.match.in_port = client_port_match
        msg.match.dl_vlan = vlan['untrusted']
        msg.match.dl_type = 0x0800
        msg.match.nw_proto = 17
        msg.match.tp_dst = 53
        msg.actions.append(of.ofp_action_vlan_vid(vlan_vid = vlan['trusted']))
        msg.actions.append(of.ofp_action_output(port = router_port_action))
        connection.send(msg)

        # permit DHCP to flow from clients to router
        msg = of.ofp_flow_mod()
        msg.priority = 20
        msg.match.in_port = client_port_match
        msg.match.dl_vlan = vlan['untrusted']
        msg.match.dl_type = 0x0800
        msg.match.nw_proto = 17
        msg.match.tp_src = 68
        msg.match.tp_dst = 67
        msg.actions.append(of.ofp_action_vlan_vid(vlan_vid = vlan['trusted']))
        msg.actions.append(of.ofp_action_output(port = router_port_action))
        connection.send(msg)

        # permit ARP to flow from clients to router (if supported)
        # otherwise, pre-authenticated clients will ARP to captive portal
        # which should be running proxy-arp so there should still be no problem
        if dp_supports_arp_match:
            msg = of.ofp_flow_mod()
            msg.priority = 20
            msg.match.in_port = client_port_match
            msg.match.dl_vlan = vlan['untrusted']
            msg.match.dl_type = pkt.ethernet.ARP_TYPE
            msg.actions.append(of.ofp_action_vlan_vid(vlan_vid = vlan['trusted']))
            msg.actions.append(of.ofp_action_output(port = router_port_action))
            connection.send(msg)        

        # send traffic from the client to the portal
        msg = of.ofp_flow_mod()
        msg.priority = 10
        msg.match.in_port = client_port_match
        msg.match.dl_vlan = vlan['untrusted']
        msg.actions.append(of.ofp_action_dl_addr.set_dst(portal))
        msg.actions.append(of.ofp_action_vlan_vid(vlan_vid = vlan['portal']))
        msg.actions.append(of.ofp_action_output(port = portal_port_action))
        connection.send(msg)


        # send IP traffic from the portal back to the client
        msg = of.ofp_flow_mod()
        msg.priority = 10
        msg.match.in_port = portal_port_match
        msg.match.dl_vlan = vlan['portal']
        msg.match.dl_src = portal
        # note - commented out because the switch under test can't match IP networks yet
        # note - this means for now that the "networks" array can only contain one network
        # note - we would have to also match ARP which is also not supported via the device under test
        #msg.match.dl_type = pkt.ethernet.IP_TYPE
        #msg.match.nw_dst = network
        msg.actions.append(of.ofp_action_vlan_vid(vlan_vid = vlan['untrusted']))
        msg.actions.append(of.ofp_action_output(port = client_port_action))
        connection.send(msg)

        # send IP traffic from the router back to the client
        msg = of.ofp_flow_mod()
        msg.priority = 10
        msg.match.in_port = router_port_match
        msg.match.dl_vlan = vlan['trusted']
        msg.match.dl_src = router
        # note - commented out because the switch under test can't match IP networks yet
        # note - this means for now that teh "networks" array can only contain one network
        # note - we would have to also match ARP which is also not supported via the device under test
        #msg.match.dl_type = pkt.ethernet.IP_TYPE
        #msg.match.nw_dst = network
        msg.actions.append(of.ofp_action_vlan_vid(vlan_vid = vlan['untrusted']))
        msg.actions.append(of.ofp_action_output(port = client_port_action))
        connection.send(msg)



def _handle_connectionup (event):
    log.debug("Captive portal starting - connection is up")
    sPortal(event.connection)



# starting point for POX to launch our application
def launch ():
    # Send full packets to controller
    core.openflow.addListenerByName("ConnectionUp",_handle_connectionup)
    core.openflow.addListenerByName("PortStatus",_handle_portstatus)
    core.openflow.addListenerByName("PacketIn",_handle_packetin)
    core.openflow.addListenerByName("FlowRemoved",_handle_flowremoved)
    server =  SimpleXMLRPCServer(("0.0.0.0",8000),allow_none=True)
    server.register_function(pClient,"pClient")
    xmlrpcThread = threading.Thread(target=server.serve_forever)
    xmlrpcThread.daemon = True
    xmlrpcThread.start()
    log.debug("NAC application running on POX controller.")
