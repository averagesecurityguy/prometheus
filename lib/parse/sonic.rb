##
# Input: A plain-text SonicWALL Technical Support Report (.wri) file
#
# Output: A Config::Firewall object
#
# Action: Parse the config line by line and update the appropriate parts of 
# the Config::Firewall object
def parse_sonic_config(config)

	fw = FWConfig::FirewallConfig.new
	fw.type = "SonicOS"

	##
	# Both Service Objects and Address Objects have "members" and the regex
	# used to identify the members is the same. This is confusing when parsing 
	# line by line because address_object members may get added to 
	# service_objects and vice versa. These flags are used to determine if we 
	# are processing a service_object or an address_object
	service_object = false
	address_object = false
	
	# Service Objects are made up of other Service Objects and ports. In the 
	# config, ports are not defined before the Service Objects that use them 
	# so we need to preproces the file to get the port names. The same is true 
	# for Address Objects, we need to preprocess the file to get host names.
	port_names, host_names = preprocess_names(config)

	##
	# Read through each line of the configuration file, use regex to identify 
	# the relevant parts of the config file, and update the Config::Firewall 
	# object as necessary.
	config.each_line do |line|

		line.chomp!

		# Get the firewall name and firmware version
		if line =~ /^Serial number (.*)/ then fw.name = $1 end
		if line =~ /^Firmware version: (.*)/ then fw.firmware = $1 end

		# Build a list of access control lists.
		if line =~ /^From ([A-Z]+ To [A-Z]+)/ then
			vprint_status("Processing access control list #{$1}.")
			fw.access_lists << Config::AccessList.new($1)
		end

		# Identify a rule and create a new Config::Rule object to store it.
		if line =~ /^Rule ([0-9]+) \(([a-zA-z]+)\)/
			vprint_status("Processing rule #{$1}.")
			rule = Config::Rule.new($1)
			if $2 == "Enabled" then rule.enabled = true end
			fw.access_lists.last.ruleset << rule
		end

		# Add the rule source
		if line =~ /^source:\s+(.*)$/
			fw.access_lists.last.ruleset.last.source = $1
		end

		# Add the rule destination
		if line =~ /^destination:\s(.*)$/
			fw.access_lists.last.ruleset.last.dest = $1
		end

		# Add the rule action and service
		if line =~ /^action:\s+(.*), service:\s+(.*)/ then
			fw.access_lists.last.ruleset.last.action = $1
			fw.access_lists.last.ruleset.last.service = $2
		end

		# Identify the interfaces in use and store them in a Config::Interface 
		# object.
		if line =~ /^Interface Name:\s+([A-Z0-9]+)/ then
			vprint_status("Processing interface #{$1}.")
			fw.interfaces << Config::Interface.new($1)
		end

		# Add the IP address to the last interface we found. 
		if line =~ /^IP Address:\s+(.*)/
			fw.interfaces.last.ip = $1
		end

		# Add the network mask to the last interface we found.
		if line =~ /^Network Mask:\s+(.*)/
			fw.interfaces.last.mask = $1
		end

		# Add the status to the last interface we found.
		if line =~ /^Port Status:\s+(.*)/
			if $1 == "UP"
				fw.interfaces.last.status = 'Up'
			else
				fw.interfaces.last.status = 'Down'
			end
		end

		# Check to see if the interface is in the WAN zone. If so, it is an 
		# external interface, otherwise it is not.
		if line =~ /^Zone:\s+WAN\s+Handle:.*$/
			fw.interfaces.last.external = true
		end

		# Determine which interfaces are running management protocols such as 
		# http, and ssh. SonicWALL does not appear to support telnet.
		if line =~ /^Interface http Management:\s+(.*)/
			if $1 == 'Yes'
				fw.interfaces.last.http = true
			end
		end

		if line =~ /^Interface https Management:\s+(.*)/
			if $1 == 'Yes'
				fw.interfaces.last.https = true
			end
		end

		if line =~ /^Interface ssh Management:\s+(.*)/
			if $1 == 'Yes'
				fw.interfaces.last.ssh = true
			end
		end

	#-------------------------------------------------------------------------
	# Professional Only Functionality
	#-------------------------------------------------------------------------

		# Parse Address Object Table
		if line =~ /^(.*): Handle:\d+ ZoneHandle:/
			name = $1.gsub(/\(.*\)/, '')
			vprint_status("Processing network name #{name}.")
			address_object = true
			service_object = false
			fw.network_names << Config::NetworkName.new(name)
		end

		# Parse Service Object Table
		if line =~ /^(.*): Handle:\d+ Size:.* GROUP:/
			vprint_status("Processing service name #{$1}.")
			address_object = false
			service_object = true
			fw.service_names << Config::ServiceName.new($1)
		end

		# Parse service object members
		if ((line =~ /^   member: Name:(.*) Handle:\d+/) && (service_object))
			print_debug("Processing service object #{$1}")
			if port_names[$1]
				fw.service_names.last.ports << port_names[$1]
			else
				fw.service_names.last.ports << 'service ' + $1
			end
		end

		# Parse address object members
		if ((line =~ /^   member: Name:(.*) Handle:\d+/) && (address_object))
			name = $1
			print_debug("Processing address object #{name}")
			if host_names[name]
				fw.network_names.last.hosts << host_names[name].gsub(/\(.*\)/, '')
			else
				fw.network_names.last.hosts << 'network ' + name
			end
		end
	end
	
	# Put the preprocessed host_names into the Config::Firewall object.
	host_names.each do |name, ip|
		fw.host_names[name] = ip
	end

	return fw
end	


##
# Input: A plain-text SonicWALL Technical Support Report (.wri) file.
# 
# Output: Two hashes, one containing a list of port_names and another 
# containing a list of host_names.
#
# Action: Parse the config looking for port names and host names, including 
# network names.
def preprocess_names(config)

	port_names = {}
	host_names = {}

	config.each_line do |line|
		line.chomp!

		# Parse Ports from the Service Object Table. Load them into port_names 
		# for later processing.
		if line =~ /^(.*): Handle:\d+ .* IpType:.*/
			name = $1
			puts line
			protocol, port_begin, port_end = parse_port_object(line)
			if port_begin == port_end
				port_names[name] = "#{protocol} #{port_begin}"
			else
				port_names[name] = "#{protocol} range #{port_begin} #{port_end}"
			end
		end

		# Parse IP addresses from Address Object Table. Load them into 
		# host_names for later processing.
		if line =~ /(.*): Handle:\d+ .* HOST: (.*)/
			name = $1
			ip = $2
			name.gsub!(/\(.*\)/, '')
			print_debug("Host Name: #{name}")
			host_names[name] = ip + '/32'
		end

		# Parse Networks from Address Object Table. Load them into host_names 
		# for later processing.
		if line =~ /(.*): Handle:\d+ .* NETWORK: (.*) - (.*)/
			name = $1
			ip = $2
			mask = $3
			name.gsub!(/\(.*\)/, '')
			print_debug("Network Name: #{name}")
			host_names[name] = ip + '/' + mask
		end

	end

	return port_names, host_names
end

##
# Input: A string
#
# Output: Three strings representing the protocol, begging port, and ending 
# port
#
# Action: Parse the given line to identify the protocol (IpType), the beginning 
# port, and the ending port. 
def parse_port_object(line)
	vprint_status("Processing port object.")

	protocol = ''
	if line =~ /Port Begin: (\d+)/
		port_begin = $1
	end

	if line =~ /Port End: (\d+)/
		port_end = $1
	end

	if line =~ /IpType: (\d+)/
		case $1
			when '1'
				protocol = 'icmp'
			when '2'
				protocol = 'igmp'
			when '6'
				protocol = 'tcp'
			when '17'
				protocol = 'udp'
			else
				protocol = 'ip_type ' + $1
		end
	end

	print_debug("Protocol: " + protocol)
	print_debug("port_begin: " + port_begin)
	print_debug("port_end: " + port_end)
	
	return protocol, port_begin, port_end
end

