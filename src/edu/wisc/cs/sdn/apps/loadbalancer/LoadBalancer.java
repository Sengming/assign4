package edu.wisc.cs.sdn.apps.loadbalancer;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import org.openflow.protocol.OFMatch;
import org.openflow.protocol.OFMatchField;
import org.openflow.protocol.OFMessage;
import org.openflow.protocol.OFOXMFieldType;
import org.openflow.protocol.OFPacketIn;
//import org.openflow.protocol.OFPortConfigTest;
import org.openflow.protocol.OFPort;
import org.openflow.protocol.OFType;
import org.openflow.protocol.action.OFAction;
import org.openflow.protocol.action.OFActionOutput;
import org.openflow.protocol.action.OFActionSetField;
import org.openflow.protocol.instruction.OFInstruction;
import org.openflow.protocol.instruction.OFInstructionActions;
import org.openflow.protocol.instruction.OFInstructionApplyActions;
import org.openflow.protocol.instruction.OFInstructionGotoTable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import edu.wisc.cs.sdn.apps.l3routing.L3Routing;
import edu.wisc.cs.sdn.apps.util.ArpServer;
import edu.wisc.cs.sdn.apps.util.SwitchCommands;
import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.IOFSwitch.PortChangeType;
import net.floodlightcontroller.core.IOFSwitchListener;
import net.floodlightcontroller.core.ImmutablePort;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.devicemanager.IDevice;
import net.floodlightcontroller.devicemanager.IDeviceService;
import net.floodlightcontroller.devicemanager.internal.DeviceManagerImpl;
import net.floodlightcontroller.packet.ARP;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.TCP;
import net.floodlightcontroller.util.MACAddress;

public class LoadBalancer implements IFloodlightModule, IOFSwitchListener,
		IOFMessageListener
{
	public static final short LOW_PRIORITY_RULE = 1;
//	public static final short MID_PRIORITY_RULE;
	public static final short HIGH_PRIORITY_RULE = 2;
	
	public static final String MODULE_NAME = LoadBalancer.class.getSimpleName();
	
	private static final byte TCP_FLAG_SYN = 0x02;
	
	private static final short IDLE_TIMEOUT = 20;
	
	// Interface to the logging system
    private static Logger log = LoggerFactory.getLogger(MODULE_NAME);
    
    // Interface to Floodlight core for interacting with connected switches
    private IFloodlightProviderService floodlightProv;
    
    // Interface to device manager service
    private IDeviceService deviceProv;
    
    // Switch table in which rules should be installed
    private byte table;
    
    // Set of virtual IPs and the load balancer instances they correspond with
    private Map<Integer,LoadBalancerInstance> instances;

    /**
     * Loads dependencies and initializes data structures.
     */
	@Override
	public void init(FloodlightModuleContext context)
			throws FloodlightModuleException 
	{
		log.info(String.format("Initializing %s...", MODULE_NAME));
		
		// Obtain table number from config
		Map<String,String> config = context.getConfigParams(this);
        this.table = Byte.parseByte(config.get("table"));
        
        // Create instances from config
        this.instances = new HashMap<Integer,LoadBalancerInstance>();
        String[] instanceConfigs = config.get("instances").split(";");
        for (String instanceConfig : instanceConfigs)
        {
        	String[] configItems = instanceConfig.split(" ");
        	if (configItems.length != 3)
        	{ 
        		log.error("Ignoring bad instance config: " + instanceConfig);
        		continue;
        	}
        	LoadBalancerInstance instance = new LoadBalancerInstance(
        			configItems[0], configItems[1], configItems[2].split(","));
            this.instances.put(instance.getVirtualIP(), instance);
            log.info("Added load balancer instance: " + instance);
        }
        
		this.floodlightProv = context.getServiceImpl(
				IFloodlightProviderService.class);
        this.deviceProv = context.getServiceImpl(IDeviceService.class);
        
        /*********************************************************************/
        /* TODO: Initialize other class variables, if necessary              */
        
        /*********************************************************************/
	}

	/**
     * Subscribes to events and performs other startup tasks.
     */
	@Override
	public void startUp(FloodlightModuleContext context)
			throws FloodlightModuleException 
	{
		log.info(String.format("Starting %s...", MODULE_NAME));
		this.floodlightProv.addOFSwitchListener(this);
		this.floodlightProv.addOFMessageListener(OFType.PACKET_IN, this);
		
		/*********************************************************************/
		/* TODO: Perform other tasks, if necessary                           */
		
		/*********************************************************************/
	}
	
	/**
     * Event handler called when a switch joins the network.
     * @param DPID for the switch
     */
	@Override
	public void switchAdded(long switchId) 
	{
		IOFSwitch sw = this.floodlightProv.getSwitch(switchId);
		log.info(String.format("Switch s%d added", switchId));
		
		/*********************************************************************/
		/* Install rules to send:                                      */
		/*       (1) packets from new connections to each virtual load       */
		/*       balancer IP to the controller                               */
		
//		 Go through all the instances, setting rules on switches to route packets if sent to virtual IP
		for (Integer balancerIp : instances.keySet())
		{
			OFMatch match = createIpMatchCriteria(balancerIp);
			match.setNetworkProtocol(OFMatch.IP_PROTO_TCP);
			OFInstructionActions instruction = createOutputInstruction(OFPort.OFPP_CONTROLLER.getValue());
			List<OFInstruction> instructionList = new LinkedList<OFInstruction>();
			instructionList.add(instruction);
			SwitchCommands.installRule(sw, table, LOW_PRIORITY_RULE, match, instructionList);	
			
		}
		
//		/*       (2) ARP packets to the controller                           */
//		
//		for (Integer balancerIp : instances.keySet())
//		{
//			OFMatch match = createArpMatchCriteria(balancerIp);
//			
//			OFInstructionActions instruction = createOutputInstruction(OFPort.OFPP_CONTROLLER.getValue());
//			List<OFInstruction> instructionList = new LinkedList<OFInstruction>();
//			instructionList.add(instruction);
//			SwitchCommands.installRule(sw, table, LOW_PRIORITY_RULE, match, instructionList);	
//			
//		}
		// Forward TCP SYN packets to the controller:
//		OFInstructionActions tcpForwardInstruction = createOutputInstruction(OFPort.OFPP_CONTROLLER.getValue());
//		List<OFInstruction> tcpForwardInstructionList = new LinkedList<OFInstruction>();
//		tcpForwardInstructionList.add(tcpForwardInstruction);
//		OFMatch tcpMatchCriteria = createIpProtoMatchCriteria(OFMatch.IP_PROTO_TCP);
//
//		SwitchCommands.installRule(sw, table, LOW_PRIORITY_RULE, tcpMatchCriteria, tcpForwardInstructionList);
		
		/*       (3) all other packets to the next rule table in the switch  */
		
		OFInstructionGotoTable instruction = new OFInstructionGotoTable(L3Routing.table);
		List<OFInstruction> instructionList = new LinkedList<OFInstruction>();
		instructionList.add(instruction);
		OFMatch matchCriteria = new OFMatch();
		matchCriteria.setDataLayerType(OFMatch.ETH_TYPE_IPV4);
		SwitchCommands.installRule(sw, table, LOW_PRIORITY_RULE, matchCriteria, instructionList);
		
		/*********************************************************************/
		
	}
	
	protected OFInstructionActions createSetIpMacInstruction(int ip, byte[] mac, int srcip, byte[] srcmac)
	{
		OFActionSetField setIp = new OFActionSetField(OFOXMFieldType.IPV4_DST, ip);
		OFActionSetField setMac = new OFActionSetField(OFOXMFieldType.ETH_DST, mac);
		
		OFActionSetField setsrcIp = new OFActionSetField(OFOXMFieldType.IPV4_SRC, srcip);
		OFActionSetField setsrcMac = new OFActionSetField(OFOXMFieldType.ETH_SRC, srcmac);
		LinkedList<OFAction> actionList = new LinkedList<OFAction>();
		actionList.add(setMac);
		actionList.add(setIp);
		actionList.add(setsrcIp);
		actionList.add(setsrcMac);
		OFInstructionApplyActions retInstruction = new OFInstructionApplyActions(actionList);
		
		return retInstruction;
	}
	
	protected OFInstructionActions createSetIpMacSrcInstruction(int ip, byte[] mac)
	{
		OFActionSetField setIp = new OFActionSetField(OFOXMFieldType.IPV4_SRC, ip);
		OFActionSetField setMac = new OFActionSetField(OFOXMFieldType.ETH_SRC, mac);
		LinkedList<OFAction> actionList = new LinkedList<OFAction>();
		actionList.add(setMac);
		actionList.add(setIp);
		OFInstructionApplyActions retInstruction = new OFInstructionApplyActions(actionList);
		
		return retInstruction;
	}
	
	protected OFInstructionActions createOutputInstruction(int port)
	{
		OFActionOutput outputAction = new OFActionOutput(port);
		LinkedList<OFAction> actionList = new LinkedList<OFAction>();
		actionList.add(outputAction);
		OFInstructionApplyActions retInstruction = new OFInstructionApplyActions(actionList);
		
		return retInstruction;
	}
	
	protected OFMatch createIpProtoMatchCriteria(byte protocol)
	{
		OFMatch matchCriteria = new OFMatch();
		OFMatchField matchField = new OFMatchField(OFOXMFieldType.IP_PROTO, protocol);
		matchCriteria.setDataLayerType(OFMatch.ETH_TYPE_IPV4);
		matchCriteria.setField(matchField);
		return matchCriteria;
	}
	
	protected LinkedList<OFMatch> createIPMacToFroMatchCriteria(Ethernet clientPacket, int hostIp)
	{
		IPv4 clientIpPacket = (IPv4)clientPacket.getPayload();
		TCP clientTcpPacket = (TCP)clientIpPacket.getPayload();
		
		LinkedList<OFMatch> retVal = new LinkedList<OFMatch>();
		
		// Ether Type
		short etherType = clientPacket.getEtherType();
		
		// IP
		int clientIp = clientIpPacket.getSourceAddress();
		
		// MAC
		byte[] clientMac = clientPacket.getSourceMACAddress();
		byte[] hostMac = getHostMACAddress(hostIp);
		
		// TCP Ports
		short clientPort = clientTcpPacket.getSourcePort();
		short hostPort = clientTcpPacket.getDestinationPort();
			
		// First, the matchFields for client to host - source client, dst host
		OFMatch clientToHostMatchCriteria = new OFMatch();
		clientToHostMatchCriteria.setDataLayerType(OFMatch.ETH_TYPE_IPV4);
		clientToHostMatchCriteria.setNetworkSource(clientIp);
		clientToHostMatchCriteria.setDataLayerSource(clientMac);
		clientToHostMatchCriteria.setNetworkProtocol(OFMatch.IP_PROTO_TCP);
		clientToHostMatchCriteria.setTransportSource(clientPort);
		
		retVal.addFirst(clientToHostMatchCriteria);
		
		// next, the matchFields for host to client - source host, dst client
		OFMatch hostToClientMatchCriteria = new OFMatch();
		hostToClientMatchCriteria.setDataLayerType(OFMatch.ETH_TYPE_IPV4);
		hostToClientMatchCriteria.setNetworkSource(hostIp);
		hostToClientMatchCriteria.setDataLayerSource(hostMac);
		hostToClientMatchCriteria.setNetworkProtocol(OFMatch.IP_PROTO_TCP);
		hostToClientMatchCriteria.setTransportSource(hostPort);
		
		retVal.addLast(hostToClientMatchCriteria);
		return retVal;
	}
	
	protected OFMatch createIpMatchCriteria(Integer ipToMatch)
	{
		OFMatch matchCriteria = new OFMatch();
		OFMatchField matchField = new OFMatchField(OFOXMFieldType.IPV4_DST, ipToMatch);
		matchCriteria.setDataLayerType(OFMatch.ETH_TYPE_IPV4);
		matchCriteria.setField(matchField);
		return matchCriteria;
	}
	
	protected OFMatch createArpMatchCriteria(Integer ipToMatch)
	{
		OFMatch matchCriteria = new OFMatch();
		OFMatchField matchField = new OFMatchField(OFOXMFieldType.IPV4_DST, ipToMatch);
		matchCriteria.setDataLayerType(OFMatch.ETH_TYPE_ARP);
		matchCriteria.setField(matchField);
		return matchCriteria;
	}
	
	protected void sendArpReply(Ethernet inPacket, IOFSwitch sw, LoadBalancerInstance virtualInstance, int inPort)
	{
		if (inPacket == null || sw == null || virtualInstance == null)
		{
			throw new NullPointerException();
		}
		ARP inArpPacket = (ARP)(inPacket.getPayload());
		
        byte [] virtualMac = virtualInstance.getVirtualMAC();
        byte [] replyToMac = inArpPacket.getSenderHardwareAddress();

        // send reply ARP
        Ethernet replyEtherPacket = new Ethernet();
        ARP replyArpPacket = new ARP();

        // First, we populate the Ethernet packet:
        replyEtherPacket.setEtherType(Ethernet.TYPE_ARP);
        replyEtherPacket.setDestinationMACAddress(replyToMac);
        replyEtherPacket.setSourceMACAddress(virtualMac);

        // Next, we populate the ARP packet:
        replyArpPacket.setHardwareType(ARP.HW_TYPE_ETHERNET);
        replyArpPacket.setProtocolType(ARP.PROTO_TYPE_IP);
        replyArpPacket.setHardwareAddressLength((byte)Ethernet.DATALAYER_ADDRESS_LENGTH);
        replyArpPacket.setProtocolAddressLength((byte)4);
        replyArpPacket.setOpCode(ARP.OP_REPLY);
        replyArpPacket.setSenderHardwareAddress(virtualMac);
        replyArpPacket.setSenderProtocolAddress(virtualInstance.getVirtualIP());
        replyArpPacket.setTargetHardwareAddress(replyToMac);
        replyArpPacket.setTargetProtocolAddress(inArpPacket.getSenderProtocolAddress());

        // Store ARP in payload of Ethernet packet and send out
        replyEtherPacket.setPayload(replyArpPacket);

		
		SwitchCommands.sendPacket(sw, (short)inPort, replyEtherPacket);
	}
	
	protected void installNewTcpConnectionRules(Ethernet ethPacket, IOFSwitch sw)
	{
		if (ethPacket == null)
			throw new NullPointerException();
		IPv4 ipPacket = (IPv4)ethPacket.getPayload();
		if (ipPacket == null)
			throw new NullPointerException();
		TCP tcpPacket = (TCP)ipPacket.getPayload();
		if (tcpPacket == null)
			throw new NullPointerException();
		
		LoadBalancerInstance vBalancer = instances.get(ipPacket.getDestinationAddress());
		
		if (vBalancer != null)
		{
			log.info("Installing rules for a TCP connection now!");
			// Ok, it's meant for a load balancer
			int nextIp = vBalancer.getNextHostIP();
			log.info("Load Balancer Next host IP is: " + IPv4.fromIPv4Address(nextIp));
			byte[] nextMac = getHostMACAddress(nextIp);
			LinkedList<OFMatch> matchList = createIPMacToFroMatchCriteria(ethPacket, nextIp);
			
			// Instructions for packets from Client to server:	
			OFInstruction destinstruction = createSetIpMacInstruction(nextIp, nextMac, vBalancer.getVirtualIP(), vBalancer.getVirtualMAC());
//			OFInstruction sourceinstruction = createSetIpMacSrcInstruction(vBalancer.getVirtualIP(), vBalancer.getVirtualMAC());
			List<OFInstruction> instructionList = new LinkedList<OFInstruction>();
			OFInstructionGotoTable clientGoToTable = new OFInstructionGotoTable(L3Routing.table);
			instructionList.add(destinstruction);
//			instructionList.add(sourceinstruction);
			instructionList.add(clientGoToTable);
			if(SwitchCommands.installRule(sw, table, HIGH_PRIORITY_RULE, matchList.getFirst(), instructionList, (short)0, IDLE_TIMEOUT))
			{
				log.info("Successfully installed client rules!");
			}
			
			// Instructions from Server to Client:
			OFInstruction serverToClientInstruction = createSetIpMacInstruction(ipPacket.getSourceAddress(), ethPacket.getSourceMACAddress(), vBalancer.getVirtualIP(), vBalancer.getVirtualMAC());
//			OFInstruction serverToClientLBInstruction = createSetIpMacSrcInstruction(vBalancer.getVirtualIP(), vBalancer.getVirtualMAC());
			List<OFInstruction> serverToClientInsList = new LinkedList<OFInstruction>();
			OFInstructionGotoTable serverGoToTable = new OFInstructionGotoTable(L3Routing.table);
			serverToClientInsList.add(serverToClientInstruction);
			serverToClientInsList.add(serverGoToTable);
//			serverToClientInsList.add(serverToClientLBInstruction);
			if(SwitchCommands.installRule(sw, table, HIGH_PRIORITY_RULE, matchList.getLast(), serverToClientInsList, (short)0, IDLE_TIMEOUT))
			{
				log.info("Successfully installed host rules!");
			}
		}
		else
		{
			log.info("Couldn't find a load balancer that matches the client IP destination!");
			// TCP syn wasn't meant for us...do nothing
		}
	}
	
	/**
	 * Handle incoming packets sent from switches.
	 * @param sw switch on which the packet was received
	 * @param msg message from the switch
	 * @param cntx the Floodlight context in which the message should be handled
	 * @return indication whether another module should also process the packet
	 */
	@Override
	public net.floodlightcontroller.core.IListener.Command receive(
			IOFSwitch sw, OFMessage msg, FloodlightContext cntx) 
	{
		// We're only interested in packet-in messages
		if (msg.getType() != OFType.PACKET_IN)
		{ return Command.CONTINUE; }
		OFPacketIn pktIn = (OFPacketIn)msg;
		
		// Handle the packet
		Ethernet ethPkt = new Ethernet();
		ethPkt.deserialize(pktIn.getPacketData(), 0,
				pktIn.getPacketData().length);
		
		/*********************************************************************/
		/* TODO: Send an ARP reply for ARP requests for virtual IPs; for TCP */
		/*       SYNs sent to a virtual IP, select a host and install        */
		/*       connection-specific rules to rewrite IP and MAC addresses;  */
		/*       ignore all other packets                                    */
		
		/*********************************************************************/
		
//		log.info("ProtocolAddr: " + IPv4.toIPv4Address(arpPacket.getTargetProtocolAddress()));
		if (ethPkt.getEtherType() == Ethernet.TYPE_ARP)
		{
			LoadBalancerInstance lbInstance = instances.get(IPv4.toIPv4Address(((ARP)ethPkt.getPayload()).getTargetProtocolAddress()));
			if (lbInstance != null)
			{
				sendArpReply(ethPkt, sw, lbInstance, pktIn.getInPort());
			}
			
			log.info("Heluu, load balancer here, I've just received an ARP packet from: ");//+ ethPkt.getSourceMAC().toString());
		}
		else
		{
			// Is it TCP then?
			IPv4 ipPkt = (IPv4)ethPkt.getPayload();
			if (ipPkt.getProtocol() == IPv4.PROTOCOL_TCP)
			{
				// IT IS TCP!!! Let's get the flag now to see if it's a SYN
				TCP tcpPkt = (TCP)ipPkt.getPayload();
				log.info("Received TCP connection! Flag is: " + tcpPkt.getFlags());
				if (tcpPkt.getFlags() == TCP_FLAG_SYN)
				{
					// Now we need to differntiate between first SYN and second, after rules have been installed, so:
					if (instances.get(ipPkt.getDestinationAddress()) != null)
					{
						installNewTcpConnectionRules(ethPkt, sw);					
					}
					else
					{
					// Else syn packet that's been changed is received
						log.info("Actually TCP packet has been changed, but still came here, not installing!");
					}

				}
				else
				{
					log.info("Non SYN TCP received!");
				}
			}
			else
			{
				log.info("I have just been sent something I'm not handling yet! It's not an ARP or TCP packet!!!");
			}
		}
		
		// We don't care about other packets
		return Command.CONTINUE;
	}
	
	/**
	 * Returns the MAC address for a host, given the host's IP address.
	 * @param hostIPAddress the host's IP address
	 * @return the hosts's MAC address, null if unknown
	 */
	private byte[] getHostMACAddress(int hostIPAddress)
	{
		Iterator<? extends IDevice> iterator = this.deviceProv.queryDevices(
				null, null, hostIPAddress, null, null);
		if (!iterator.hasNext())
		{ return null; }
		IDevice device = iterator.next();
		return MACAddress.valueOf(device.getMACAddress()).toBytes();
	}

	/**
	 * Event handler called when a switch leaves the network.
	 * @param DPID for the switch
	 */
	@Override
	public void switchRemoved(long switchId) 
	{ /* Nothing we need to do, since the switch is no longer active */ }

	/**
	 * Event handler called when the controller becomes the master for a switch.
	 * @param DPID for the switch
	 */
	@Override
	public void switchActivated(long switchId)
	{ /* Nothing we need to do, since we're not switching controller roles */ }

	/**
	 * Event handler called when a port on a switch goes up or down, or is
	 * added or removed.
	 * @param DPID for the switch
	 * @param port the port on the switch whose status changed
	 * @param type the type of status change (up, down, add, remove)
	 */
	@Override
	public void switchPortChanged(long switchId, ImmutablePort port,
			PortChangeType type) 
	{ /* Nothing we need to do, since load balancer rules are port-agnostic */}

	/**
	 * Event handler called when some attribute of a switch changes.
	 * @param DPID for the switch
	 */
	@Override
	public void switchChanged(long switchId) 
	{ /* Nothing we need to do */ }
	
    /**
     * Tell the module system which services we provide.
     */
	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() 
	{ return null; }

	/**
     * Tell the module system which services we implement.
     */
	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> 
			getServiceImpls() 
	{ return null; }

	/**
     * Tell the module system which modules we depend on.
     */
	@Override
	public Collection<Class<? extends IFloodlightService>> 
			getModuleDependencies() 
	{
		Collection<Class<? extends IFloodlightService >> floodlightService =
	            new ArrayList<Class<? extends IFloodlightService>>();
        floodlightService.add(IFloodlightProviderService.class);
        floodlightService.add(IDeviceService.class);
        return floodlightService;
	}

	/**
	 * Gets a name for this module.
	 * @return name for this module
	 */
	@Override
	public String getName() 
	{ return MODULE_NAME; }

	/**
	 * Check if events must be passed to another module before this module is
	 * notified of the event.
	 */
	@Override
	public boolean isCallbackOrderingPrereq(OFType type, String name) 
	{
		return (OFType.PACKET_IN == type 
				&& (name.equals(ArpServer.MODULE_NAME) 
					|| name.equals(DeviceManagerImpl.MODULE_NAME))); 
	}

	/**
	 * Check if events must be passed to another module after this module has
	 * been notified of the event.
	 */
	@Override
	public boolean isCallbackOrderingPostreq(OFType type, String name) 
	{ return false; }
}
