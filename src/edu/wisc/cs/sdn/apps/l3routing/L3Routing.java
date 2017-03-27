package edu.wisc.cs.sdn.apps.l3routing;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.concurrent.ConcurrentHashMap;
import java.lang.Integer;
import java.net.InetSocketAddress;

import org.openflow.protocol.OFMatch;
import org.openflow.protocol.OFMatchField;
import org.openflow.protocol.OFOXMFieldType;
import org.openflow.protocol.action.OFAction;
import org.openflow.protocol.action.OFActionOutput;
import org.openflow.protocol.instruction.OFInstruction;
import org.openflow.protocol.instruction.OFInstructionActions;
import org.openflow.protocol.instruction.OFInstructionApplyActions;
import org.openflow.protocol.instruction.OFInstructionType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ch.qos.logback.core.joran.action.Action;
import edu.wisc.cs.sdn.apps.util.Host;
import edu.wisc.cs.sdn.apps.util.SwitchCommands;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.IOFSwitch.PortChangeType;
import net.floodlightcontroller.core.IOFSwitchListener;
import net.floodlightcontroller.core.ImmutablePort;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.devicemanager.IDevice;
import net.floodlightcontroller.devicemanager.IDeviceListener;
import net.floodlightcontroller.devicemanager.IDeviceService;
import net.floodlightcontroller.linkdiscovery.ILinkDiscoveryListener;
import net.floodlightcontroller.linkdiscovery.ILinkDiscoveryService;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.routing.Link;

public class L3Routing implements IFloodlightModule, IOFSwitchListener, 
		ILinkDiscoveryListener, IDeviceListener
{
	public static final String MODULE_NAME = L3Routing.class.getSimpleName();
	
	protected static enum rulePriority
	{
		LOW_PRIORITY_RULE,
		MID_PRIORITY_RULE,
		HIGH_PRIORITY_RULE
	}
	
	// Interface to the logging system
    private static Logger log = LoggerFactory.getLogger(MODULE_NAME);
    
    // Interface to Floodlight core for interacting with connected switches
    private IFloodlightProviderService floodlightProv;

    // Interface to link discovery service
    private ILinkDiscoveryService linkDiscProv;

    // Interface to device manager service
    private IDeviceService deviceProv;
    
    // Switch table in which rules should be installed
    public static byte table;
    
    // Map of hosts to devices
    private Map<IDevice,Host> knownHosts;
    
    // List of hosts no longer connected to devices
    private Map<IDevice, Host> unconnectedHosts;

	//
//	private Map<Long, Integer> distance;
//	private Map<Long, Long> predecessor;
	//
	
	/**
     * Loads dependencies and initializes data structures.
     */
	@Override
	public void init(FloodlightModuleContext context)
			throws FloodlightModuleException 
	{
		log.info(String.format("Initializing %s...", MODULE_NAME));
		Map<String,String> config = context.getConfigParams(this);
        table = Byte.parseByte(config.get("table"));
        
		this.floodlightProv = context.getServiceImpl(
				IFloodlightProviderService.class);
        this.linkDiscProv = context.getServiceImpl(ILinkDiscoveryService.class);
        this.deviceProv = context.getServiceImpl(IDeviceService.class);
        
        this.knownHosts = new ConcurrentHashMap<IDevice,Host>();
        this.unconnectedHosts = new ConcurrentHashMap<IDevice, Host>();
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
		this.linkDiscProv.addListener(this);
		this.deviceProv.addListener(this);
		
		/*********************************************************************/
		/* TODO: Initialize variables or perform startup tasks, if necessary */

		/*********************************************************************/
	}
//	
//	public class LinkPackage
//	{
//		public LinkPackage(HashMap<Long, Integer> dist, HashMap<Long, Long> pred)
//		{
//			distance = dist;
//			predecessor = pred;
//		}
//		public HashMap<Long, Integer> distance;
//		public HashMap<Long, Long> predecessor;
//	}
	
	/**Shortest-Path Algorithm**/
	//edges contains edges between switches, no hosts involved
	//The Long is the switch DPID, which I think is what uniquely identifies a switch
	//TODO: check syntax, whether it's really a HashMap, etc. What is the Collection?
	public HashMap<Long, Long> BellmanFord(Map<Long, IOFSwitch> switches, Collection<Link> links, Long src)
	{
		HashMap<Long, Integer> distance = new HashMap<Long, Integer>();
		HashMap<Long, Long> predecessor = new HashMap<Long, Long>();
		//get switches
		ArrayList<Long> switchList = new ArrayList<Long>();
		for (Long sw : switches.keySet())
		{
			switchList.add(sw);
		}
		
		//get links between switches
		ArrayList<Link> edges = new ArrayList<Link>();
		for (Link link : links) //?????
		{
			long linkSource = link.getSrc();
			long linkDest = link.getDst();
			
			if (switchList.contains(linkSource) && switchList.contains(linkDest))
			{
				edges.add(link);
			}
			
		}
		
		// Step 1: initialize graph
		for (int i = 0; i < switchList.size(); i++)
		{
			distance.put(switchList.get(i), Integer.MAX_VALUE);
			predecessor.put(switchList.get(i), null);
		}
		distance.put(src, 0);
		
		// Step 2: relax edges repeatedly
		for (int j = 0; j < switchList.size() - 1; j++) 
		{
			for (int k = 0; k < edges.size(); k++)
			{
				Link e = edges.get(k);
				Long u = e.getSrc();
				Long v = e.getDst();
				if ((distance.get(u) != Integer.MAX_VALUE) && (distance.get(u) + 1 < distance.get(v)))
				{
					distance.put(v, distance.get(u) + 1);
					predecessor.put(v, u);
				}
			}
		}

   return predecessor;
	}
	
    /**
     * Get a list of all known hosts in the network.
     */
    private Collection<Host> getHosts()
    { return this.knownHosts.values(); }
	
    private Collection<Host> getUnconnectedHosts()
    {
    	return this.unconnectedHosts.values();
    }
    /**
     * Get a map of all active switches in the network. Switch DPID is used as
     * the key.
     */
	private Map<Long, IOFSwitch> getSwitches()
    { return floodlightProv.getAllSwitchMap(); }
	
    /**
     * Get a list of all active links in the network.
     */
    private Collection<Link> getLinks()
    { return linkDiscProv.getLinks().keySet(); }

    /**
     * Event handler called when a host joins the network.
     * @param device information about the host
     */
	@Override
	public void deviceAdded(IDevice device) 
	{
		Host host = new Host(device, this.floodlightProv);
		// We only care about a new host if we know its IP
		if (host.getIPv4Address() != null)
		{
			log.info(String.format("Host %s added", host.getName()));
			this.knownHosts.put(device, host);
			
			/*****************************************************************/
			/* Update routing: add rules to route to new host          */
			/*****************************************************************/
//			Map<Long, IOFSwitch> switchList = this.getSwitches();
//			for (Long switchDPID : switchList.keySet())
//			{
				if (host.isAttachedToSwitch())
				{
					OFInstructionActions action = createOutputInstruction(host.getPort());
					OFMatch match = createMatchCriteria(host.getIPv4Address());
					List<OFInstruction> instructions = new LinkedList<OFInstruction>();
					instructions.add(action);
					SwitchCommands.installRule(host.getSwitch(), table, (short)999, match, instructions);
					// Install rule on other switches:
					recalculateRulesIfHostAdded(host.getSwitch(), host);
				}
//				else
//				{
//					
//				}
//				Collection<Host> hostList = this.getHosts();
//				LinkedList<Host> connectedHost = getConnectedHosts(hostList, switchList.get(switchDPID));
//				for (Host conhost : connectedHost)
//				{
//					OFInstructionActions action = createOutputInstruction(conhost.getPort());
//					OFMatch match = createMatchCriteria(conhost.getIPv4Address(), switchList.get(switchDPID));
//					List<OFInstruction> instructions = new LinkedList<OFInstruction>();
//					instructions.add(action);
//					SwitchCommands.installRule(switchList.get(switchDPID), table, (short)999, match, instructions);
//					log.info("S"+switchDPID+" Installing rule for host: "+ conhost.getIPv4Address() + " on port: " + conhost.getPort() );
//				}
//			}
		}
	}

	/**
     * Event handler called when a host is no longer attached to a switch.
     * @param device information about the host
     */
	@Override
	public void deviceRemoved(IDevice device) 
	{
		Host host = this.knownHosts.get(device);
		if (null == host)
		{ return; }
		this.unconnectedHosts.put(device, host);
		this.knownHosts.remove(device);
		log.info(String.format("Host %s is no longer attached to a switch", 
				host.getName()));
		
		/*********************************************************************/
		/* TODO: Update routing: remove rules to route to host               */
		
		/*********************************************************************/

		Map<Long, IOFSwitch> switchMap = this.getSwitches();
		for (Entry<Long, IOFSwitch> switchEntry : switchMap.entrySet())
		{
			SwitchCommands.removeRules(switchEntry.getValue(), table, createMatchCriteria(host.getIPv4Address()));
		}
		
	}

	/**
     * Event handler called when a host moves within the network.
     * @param device information about the host
     */
	@Override
	public void deviceMoved(IDevice device) 
	{
		Host host = this.knownHosts.get(device);
		if (null == host)
		{
			host = new Host(device, this.floodlightProv);
			this.knownHosts.put(device, host);
			
			OFInstructionActions action = createOutputInstruction(host.getPort());
			OFMatch match = createMatchCriteria(host.getIPv4Address());
			List<OFInstruction> instructions = new LinkedList<OFInstruction>();
			instructions.add(action);
			SwitchCommands.installRule(host.getSwitch(), table, (short)999, match, instructions);
			// Install rule on other switches:
			recalculateRulesIfHostAdded(host.getSwitch(), host);
		}
		
		if (!host.isAttachedToSwitch())
		{
			this.deviceRemoved(device);
			return;
		}
		log.info(String.format("Host %s moved to s%d:%d", host.getName(),
				host.getSwitch().getId(), host.getPort()));
		
		/*********************************************************************/
		/* TODO: Update routing: change rules to route to host               */
		
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
		recalculateRulesIfSwitchAdded();
		/*********************************************************************/
		/* TODO: Update routing: change routing rules for all hosts          */
		
		/*********************************************************************/
	}

	/**
	 * Event handler called when a switch leaves the network.
	 * @param DPID for the switch
	 */
	@Override
	public void switchRemoved(long switchId) 
	{
		IOFSwitch sw = this.floodlightProv.getSwitch(switchId);
		log.info(String.format("Switch s%d removed", switchId));
		
		/*********************************************************************/
		/* TODO: Update routing: change routing rules for all hosts          */
		
		/*********************************************************************/
	}

	/**
	 * Event handler called when multiple links go up or down.
	 * @param updateList information about the change in each link's state
	 */
	@Override
	public void linkDiscoveryUpdate(List<LDUpdate> updateList) 
	{
		for (LDUpdate update : updateList)
		{
			log.info(update.toString());
			log.info(update.getOperation().toString());
			
			// If we only know the switch & port for one end of the link, then
			// the link must be from a switch to a host
			if (0 == update.getDst())
			{
				if (update.getOperation() == UpdateOperation.PORT_UP)
				{
					
					for (Entry<IDevice, Host> host : this.unconnectedHosts.entrySet())
					{
//						log.info("Host is: " + host.getValue().getName() +" Update source is: " + update.getSrc());
//						log.info("Host Port: " + host.getValue().getSwitch().toString());
//						log.info("Host: " + host.getValue().toString());
//						log.info("Host Switch ID: " + host.getValue().getSwitch().getId());
						OFInstructionActions action = createOutputInstruction(update.getSrcPort());
						OFMatch match = createMatchCriteria(host.getValue().getIPv4Address());
						List<OFInstruction> instructions = new LinkedList<OFInstruction>();
						instructions.add(action);
						SwitchCommands.installRule(getSwitches().get(update.getSrc()), table, (short)999, match, instructions);
						// Install rule on other switches:
						recalculateRulesIfHostAdded(getSwitches().get(update.getSrc()), host.getValue());
						
						this.knownHosts.put(host.getKey(), host.getValue());
						this.unconnectedHosts.remove(host.getKey());
					}
				}
				log.info(String.format("Link s%s:%d -> host updated", 
					update.getSrc(), update.getSrcPort()));

			}
			// Otherwise, the link is between two switches
			else
			{
//				log.info("Switch link added, recalculating rules!");
					recalculateRulesIfSwitchAdded();
					log.info(String.format("Link s%s:%d -> s%s:%d updated", 
						update.getSrc(), update.getSrcPort(),
						update.getDst(), update.getDstPort()));

			}
		}
	}
	
	/**
	 * Helper function to recalculate rules to add to switches. Called when new link discovered.
	 */
	public void recalculateRulesIfSwitchAdded()
	{
//		log.info("Switch added, recalculating rules!");
		Collection<Host> hostList = this.getHosts();

		for (Host host : hostList)
		{
			recalculateRulesIfHostAdded(host.getSwitch(), host);
		}
	}
	
	public void recalculateRulesIfHostAdded(IOFSwitch sourceSwitch, Host addedHost)
	{
		Map<Long, IOFSwitch> switchList = this.getSwitches();
		
		if (sourceSwitch == null)
			return;
		
		HashMap<Long, Long> predecessorMap = BellmanFord(switchList, getLinks(), sourceSwitch.getId());
		// Go through all switches
		for (IOFSwitch selectedSwitch : switchList.values())
		{
			if (selectedSwitch != sourceSwitch)
			{
//				log.info("Predecessor for switch " + selectedSwitch.getId() +" to get to " + sourceSwitch.getId()+ " is " + predecessorMap.get(selectedSwitch.getId()));
				LinkedList<Long> path = installRulesAndGetPaths(selectedSwitch, predecessorMap, addedHost, sourceSwitch);
			}
		}
	}
	
	public LinkedList<Long> installRulesAndGetPaths(IOFSwitch destinationSwitch, HashMap <Long, Long> predecessorList, Host host, IOFSwitch sourceSwitch)
	{	
		LinkedList<Long> retVal = new LinkedList<Long>();
		Long switchDpid = destinationSwitch.getId();
		Collection<Link> linksList = getLinks();
		
		// Goes through predecessor list, going backwards from destination to source switch and installing rules on them.
		while (predecessorList.containsKey(switchDpid) && switchDpid != null)
		{
			Long predecessorSwitch = predecessorList.get(switchDpid);
			if (predecessorSwitch == null)
			{
				break;
			}
//			log.info("Installing rule to switch S" + destinationSwitch.getId() + " for host :" + IPv4.fromIPv4Address(host.getIPv4Address()));
			
			
			// Setting up instructions:
			OFInstructionActions action = null;
			for (Link link : linksList)
			{
//				log.info("link.getDst(): " + link.getDst() + " link.getSrc(): " + link.getSrc());
//				log.info("switchDPID: " + switchDpid + " predecessorSwitch: " + predecessorSwitch);
				// Either way, if the link bridges between the current switch and the predecessor, get port and output
				if ((link.getDst() == switchDpid) && (link.getSrc() == predecessorSwitch))
				{
					action = createOutputInstruction(link.getDstPort());
				}
				else if ((link.getSrc() == switchDpid) && (link.getDst() == predecessorSwitch))
				{
					action = createOutputInstruction(link.getSrcPort());
				}
			}
			OFMatch match = createMatchCriteria(host.getIPv4Address());
			List<OFInstruction> instructions = new LinkedList<OFInstruction>();
			instructions.add(action);
			
			SwitchCommands.installRule(getSwitches().get(switchDpid), table, (short)999, match, instructions);		
			
			retVal.add(switchDpid);
			switchDpid = predecessorSwitch;
//			log.info("switchDpid is " +switchDpid);
//			log.info("sourceSwitch is " + sourceSwitch.getId());
			if (switchDpid == null || switchDpid == sourceSwitch.getId())
			{
				// We've gone back from destination and arrived at source. Exit loop.
				break;
			}
		}
		return retVal;
	}
	
	/**
	 * Helper function to return a linked list of hosts connected to a particular switch.
	 */
	public LinkedList<Host> getConnectedHosts(Collection<Host> hostList, IOFSwitch ofSwitch)
	{
		LinkedList<Host> retVal = new LinkedList<Host>();
		
		// Iterate over all hosts in the host list,
		for (Host host : hostList)
		{
			// If the switch the host is attached to matches the passed in switch, append to list:
			if (host.getSwitch() == ofSwitch)
			{
				retVal.add(host);
			}
		}
		return retVal;
	}
	
	public OFInstructionActions createOutputInstruction(int port)
	{
		OFActionOutput outputAction = new OFActionOutput(port);
		LinkedList<OFAction> actionList = new LinkedList<OFAction>();
		actionList.add(outputAction);
		OFInstructionApplyActions retInstruction = new OFInstructionApplyActions(actionList);
		
		return retInstruction;
	}
	
	public OFMatch createMatchCriteria(Integer connectedIP)
	{
		OFMatch matchCriteria = new OFMatch();
		OFMatchField matchField = new OFMatchField(OFOXMFieldType.IPV4_DST, connectedIP);
		matchCriteria.setDataLayerType(OFMatch.ETH_TYPE_IPV4);
		matchCriteria.setField(matchField);
		return matchCriteria;
	}

	/**
	 * Event handler called when link goes up or down.
	 * @param update information about the change in link state
	 */
	@Override
	public void linkDiscoveryUpdate(LDUpdate update) 
	{ this.linkDiscoveryUpdate(Arrays.asList(update)); }
	
	/**
     * Event handler called when the IP address of a host changes.
     * @param device information about the host
     */
	@Override
	public void deviceIPV4AddrChanged(IDevice device) 
	{ this.deviceAdded(device); }

	/**
     * Event handler called when the VLAN of a host changes.
     * @param device information about the host
     */
	@Override
	public void deviceVlanChanged(IDevice device) 
	{ /* Nothing we need to do, since we're not using VLANs */ }
	
	/**
	 * Event handler called when the controller becomes the master for a switch.
	 * @param DPID for the switch
	 */
	@Override
	public void switchActivated(long switchId) 
	{ /* Nothing we need to do, since we're not switching controller roles */ }

	/**
	 * Event handler called when some attribute of a switch changes.
	 * @param DPID for the switch
	 */
	@Override
	public void switchChanged(long switchId) 
	{ /* Nothing we need to do */ }
	
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
	{ /* Nothing we need to do, since we'll get a linkDiscoveryUpdate event */ }

	/**
	 * Gets a name for this module.
	 * @return name for this module
	 */
	@Override
	public String getName() 
	{ return this.MODULE_NAME; }

	/**
	 * Check if events must be passed to another module before this module is
	 * notified of the event.
	 */
	@Override
	public boolean isCallbackOrderingPrereq(String type, String name) 
	{ return false; }

	/**
	 * Check if events must be passed to another module after this module has
	 * been notified of the event.
	 */
	@Override
	public boolean isCallbackOrderingPostreq(String type, String name) 
	{ return false; }
	
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
        floodlightService.add(ILinkDiscoveryService.class);
        floodlightService.add(IDeviceService.class);
        return floodlightService;
	}
}
