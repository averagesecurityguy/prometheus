##
# Input: A plain-text Cisco ASA configuration file
#
# Output: A FWConfig::FirewallConfig object
#
# Action: Parse the config line by line and update the appropriate parts of 
# the FWConfig::Firewall object
def parse_cisco_config(config)		
    
	@fw = FWConfig::FirewallConfig.new

    parse_host_names(config)
    parse_network_service_objects(config)
    parse_access_lists(config)
    parse_settings(config)

	return @fw
end

def parse_settings(config)
	##
	# Read through each line of the configuration file, use regex to identify 
	# the relevant parts of the config file, and update the FWConfig::Firewall 
	# object as necessary.
	config.each_line do |line|

		line.chomp!

		# Identify the host name
		if line =~ /^hostname (.*)$/ then @fw.name = $1  end

		# The same code is used to parse both ASA and PIX files but still need 
		# to know the file type for reporting purposes.
		if line =~ /ASA Version (.*)$/
			@fw.firmware = $1
			@fw.type = 'ASA'
		end

		if line =~ /PIX Version (.*)$/
			@fw.firmware = $1
			@fw.type = 'PIX'
		end

		# Build a list of interfaces on the device.
		if line =~ /^interface (.*)/ then
			vprint_status("Processing interface #{$1}")
			@fw.interfaces << FWConfig::Interface.new($1)
		end
		interface = @fw.interfaces.last

		# Rename the interface if nameif is defined
		if line =~ /^ nameif ([a-zA-Z0-9\/]+)/ then
			interface.name = $1
		end

		# Get the IP address and mask for the interface
		if line =~ /^ ip address (.*)/
			ip, mask = $1.split(" ")
			p ip
			puts ip
			case ip
			when /\d+\.\d+.\d+.\d+/
				print_debug("Processing as ip")
				interface.ip = ip
			when 'dhcp'
				print_debug("Processing as 'debug'")
				interface.ip = ip
			else
				print_debug("Processing as hostname")
				interface.ip = @fw.host_names[ip]
			end
			
			interface.mask = mask
		end

		# Determine the status of the interface based on the shutdown command.
		if line =~ /^ shutdown/
			interface.status = "Down"
		end

		# Determine if the interface is external based on security level 0.
		if line =~ /^ security-level (\d+)/
			if $1 == 0 then interface.external = true end
		end

		# Determine which interfaces are running management protocols such as 
		# http, ssh, and telnet. Have to loop through the interface names to 
		# determine which interface the management protocol is running on.
		if line =~ /^http .*\s.*\s(.*)/ then
			vprint_status line
			@fw.interfaces.each do |int|
				if int.name == $1 then int.http = true end
			end
		end

		if line =~ /^ssh .*\s.*\s(.*)/ then
			vprint_status line
			@fw.interfaces.each do |int|
				if int.name == $1 then int.ssh = true end
			end
		end

		if line =~ /^telnet .*\s.*\s(.*)/ then
			vprint_status line
			@fw.interfaces.each do |int|
				if int.name == $1 then int.telnet = true end
			end
		end	

	end
	
end


#-----------------------------------------------------------------------------
# Additional methods needed for parsing the config file.
#-----------------------------------------------------------------------------

##
# Input: A FWConfig::FirewallConfig object and a firewall config file
#
# Output: A list of host names and IP addresses
#
# Action: Create a hash of hostname to IP address mappings
def parse_host_names(config)
	config.each_line do |line|

		line.chomp!

		# Find host names in use
		if line =~ /^name (\d+\.\d+.\d+.\d+) (.*)/
			@fw.host_names[parse_ip_name($2)] = $1
		end
	end
end
	
##
# Input: A FWConfig::FirewallConfig object and a firewall config file
#
# Output: A hash of network objects and a hash of service objects.
#
# Action: Parse the configuration file

def parse_network_service_objects(config)
	##
	# Both network objects and service objects can contain group objects, 
	# which is confusing when parsing line by line because the group object 
	# may get associated with a network object when it should have been
	# associated with a service object, or vice versa. This variable is used 
	# to determine if we are processing a network object or a service object. 
	process_network = false

	##
	# Read through each line of the configuration file, use regex to identify 
	# the relevant parts of the config file, and update the FWConfig::Firewall 
	# object as necessary.
	config.each_line do |line|

		line.chomp!
		
		# HOW TO PROCESS THESE
		#object network CANON_PRINTER
		#host 192.168.0.26
		#object network Ventrilo_tcp
		#host 192.168.0.6
		#description Ventrilo Server
		#object network ventrilo_udp
		#host 192.168.0.6
		#
		
		# Build a list of NetworkName objects. In ASA versions prior to 7.x
		# Cisco identifies network names with the object-group network command.
		# Each object-group is made up of network-objects and group-objects.
		# In ASA version 8.x Cisco uses the object network <name> command. 
		if line =~ /object network (.*)/
			vprint_status("Processing network group: " + $1)
			@fw.network_names << FWConfig::NetworkName.new($1)
			process_network = true
		end
		
		if line =~ /^ host (.*)/
			vprint_status("Processing network object: " + $1)
			@fw.network_names.last.hosts << $1
		end
		
		if line =~ /object-group network (.*)/
			vprint_status("Processing network group: " + $1)
			@fw.network_names << FWConfig::NetworkName.new($1)
			process_network = true
		end

		# Add the network-object information to the last NetworkName we found. 
		if line =~ /^ network-object (.*)/
			print_debug("Network Object: #{line}")
			network = $1
			if network =~ /host (.*)/
				vprint_status("Processing network object: " + $1)
				@fw.network_names.last.hosts << $1 + "/32"
			else
				vprint_status("Processing network object: " + network)
				@fw.network_names.last.hosts << network
		    end
		end
		
		# If we find a network object-group and we have a group-object then we 
		# add it to the last NetworkName we found.
		if ((line =~ /^ group-object (.*)/) && (process_network))
			vprint_status("Processing network group-object: " + $1)
			@fw.network_names.last.hosts << 'group ' + $1
		end

		# Build a list of ServiceName objects. Cisco identifies service names 
		# with the object-group service command. Each object-group is made up 
		# of service-objects, group-objects and port-objects.
		if line =~ /object-group service (.*)/
			vprint_status("Processing service group: " + $1)
			name, protocol = parse_service_object($1)
			@fw.service_names << FWConfig::ServiceName.new(name)
			@fw.service_names.last.protocol = protocol
			process_network = false
		end

		# Add the service-object information to the last ServiceName we found. 
		if line =~ /^ service-object (.*) (range|eq) (.*)/
			vprint_status("Processing service object")
			protocol = $1
			ports = $3
			port = ''
			
			if $2 == 'range'
				port = "#{protocol} range #{ports}"
			else
				port = "#{protocol} #{ports}"
			end

			print_debug("Port: #{port}")
			@fw.service_names.last.ports << port
		end

		# if we are not processing a network-object the we are processing a 
		# service-object and need to add the group-object information to the 
		# last ServiceName we identified.
		if ((line =~ /^ group-object (.*)/) && (not process_network))
			vprint_status("Processing service group-object: " + $1)
			@fw.service_names.last.ports << 'group ' + $1
		end

		# Add the port-object information to the last ServiceName found. The 
		# protocol for the port-object is determined by the protocol of the 
		# service object-group.
		if line =~ /^ port-object (eq|range) (.*)/
			vprint_status("Processing port-object: ")
			protocol = @fw.service_names.last.protocol
			port = ''

			if $1 == 'range'
				port = "#{protocol} range #{$2}"
			else
				port = "#{protocol} #{$2}"
			end

			print_debug("Port: #{port}")
			@fw.service_names.last.ports << port
		end
	end
end


def parse_access_lists(config)
	config.each_line do |line|

		line.chomp!

		# Build a list of AccessList objects. Cisco gives the name of the 
		# access-list on each line. If there are no AccessLists in the config 
		# yet then this is a new AccessList object. If the name doesn't match 
		# the name of the last AccessList object then this is a new 
		# access-list. Otherwise we add the access-list information to the 
		# last AccessList object.
		if line =~ /access-list .* inactive .*/ then next end
 		if line =~ /access-list (.*) extended (.*)/ then
			if @fw.access_lists.last == nil
				vprint_status("Processing access list: " + $1)
				@fw.access_lists << FWConfig::AccessList.new($1)
				@fw.access_lists.last.ruleset << parse_rule(1, $2)
			elsif @fw.access_lists.last.name != $1
				vprint_status("Processing access list: " + $1)
				@fw.access_lists << FWConfig::AccessList.new($1)
				@fw.access_lists.last.ruleset << parse_rule(1, $2)
			else
				num = @fw.access_lists.last.ruleset.last.num + 1
				@fw.access_lists.last.ruleset << parse_rule(num, $2)
			end
		end

		# Use the access-group command to determine which access-lists are 
		# applied to the interfaces.
		if line =~ /^access-group (.*)/
			name, dir, int, int_name = $1.split(" ")
			vprint_status("Processing access-group: " + name)
			@fw.access_lists.each do |al|
				if al.name == name then al.interface = int_name end
			end
		end
	end
end

	
##
# Input: A space delimited string representing an access control entry (rule)
#
# Output: A Rule object
#
# Action: Create a new Rule object and set the properties.
#
# Note: Technically a rule can have both a source service and a destination 
# service. Currently only storing destination services because that is what 
# I see most often. Need to consider how to handle both.
def parse_rule(id, string)
	rule = FWConfig::Rule.new(id)
	print_debug("Rule: #{string}")

	# By default the rule is enabled.
	rule.enabled = true

	rule_array = string.split(" ")
	rule.action = parse_action(rule_array.shift)
	rule.protocol, rule_array = parse_rule_protocol(rule_array)
	rule.source, rule_array = parse_rule_host(rule_array)

	# capture the source service but not sure what to do with it yet.
	if rule.protocol != 'icmp'
		source_service, rule_array = parse_rule_service(rule_array)
	end

	rule.dest, rule_array = parse_rule_host(rule_array)
	rule.service, rule_array = parse_rule_service(rule_array)

	# If the end of the rule includes the word 'inactive' then the rule is 
	# disabled.
	if rule_array.include?('inactive')
		rule.enabled = false
	end

	print_debug("Enabled: #{rule.enabled}")

	return rule
  
end

##
# Input: A string
#
# Output: A string with either 'Deny' or 'Allow'
def parse_action(str)
	action = 'Deny'
	if str == 'permit' then action = 'Allow' end

	print_debug("Action: #{action}")
	return action
end

##
# Input: An array containing a partial access control entry
#
# Output: A string with the protocol and an array with the rest of the rule
#
# Action: If the first entry in the array is object-group then the protocol 
# is a service object, otherwise the first entry is the protocol.
def parse_rule_protocol(rule_array)
	str = rule_array.shift
	case str
		when nil
			protocol = ''
		when "object-group"
			protocol = rule_array.shift
		else
			protocol = str
	end

	print_debug("Protocol: #{protocol}")
	return protocol, rule_array
end

##
# Input: An array containing a partial access control entry
#
# Output: A string with the host and an array with the rest of the rule
#
# Action: If the first entry in the array is any then the host is "Any", if it 
# is host then the host is the next entry in the array and has a mask of /32, 
# if it is object-group then the host is a network object, otherwise it is the 
# the host and the next entry in the array is the subnet mask.
def parse_rule_host(rule_array)
	str = rule_array.shift
	print_debug("Str: #{str}")
	case str
		when nil
			host = ''
		when "any"
			host = "Any"
		when "host"
			host = rule_array.shift + "/32"
		when "object-group"
			if @fw.network?(rule_array[0])
				host = rule_array.shift
			else
				rule_array.unshift(str)
				host = 'Any'
			end
		when "object"
			if @fw.network?(rule_array[0])
				host = rule_array.shift
			else
				rule_array.unshift(str)
				host = 'Any'
			end
		else
			host = str + "/" + rule_array.shift
	end

	print_debug("Host: #{host}")
	return host, rule_array
end

##
# Input: An array containing a partial access control entry
#
# Output: A string with the protocol and an array with the rest of the rule
#
# Action: If the first entry in the array is nil then we are at the end of the 
# rule and the service is "Any", if it is lt, gt, eq, neq or range then the
# next entry in the array is the port but is modified by the operator, if it 
# is object-group then the service is a service name, otherwise the service is 
# "Any".
def parse_rule_service(rule_array)
	str = rule_array.shift
	case str
		when nil
			service = 'Any'
		when "lt"
			service = '1 - ' + rule_array.shift
		when "gt"
			service = rule_array.shift + ' - 65535'
		when "eq"
			service = rule_array.shift
		when "neq"
			service = 'not ' + rule_array.shift
		when "range"
			service = rule_array.shift + " - " + rule_array.shift
		when "object-group"
			if @fw.service?(rule_array[0])
				service = rule_array.shift
			else
				rule_array.unshift(str)
				service = 'Any'
			end
		else
			rule_array.unshift(str)
			service = 'Any'
    end

	print_debug("Service: #{service}")
	return service, rule_array
end

##
# Input: A string
#
# Output: A string with an IP address
#
# Action: A name entry has an optional description. We filter this out and 
# return only the IP address associated with the host name. 
def parse_ip_name(str)
	ip_name = str
	if str =~ /(.*) description (.*)/
		ip_name = $1
	end

	print_debug("IP Address: #{ip_name}")
	return ip_name
end

##
# Input: A string
#
# Output: Two strings, one with the service name the other with the protocol
#
# Action: A service object can optionally define the protocol. If the protocol 
# is defined then we return it, otherwise we set th protocol to 'tcp'
def parse_service_object(str)
	name = protocol = ''
	if str =~ /(.*) (tcp|udp|tcp-udp)$/
		name = $1
		protocol = $2
	else
		name = str
		protocol = 'tcp'
	end

	print_debug("Name: #{name}")
	print_debug("Protocol: #{protocol}")
	return name, protocol

end

