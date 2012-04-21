def parse_sonic_config(config)

	fw = Config::FirewallConfig.new
	fw.type = "SonicOS"
	service_object = false
	address_object = false
	
	# Sonicwall only uses names in the service object groups. We preprocess
	# the port names by reading the config through once and capturing the port 
	# names. After that we can use the port names when setting up the service 
	# object groups.
	port_names = preprocess_port_names(config)

	config.each_line do |line|
		line.chomp!
		if line =~ /^Serial number (.*)/ then fw.name = $1 end
		if line =~ /^Firmware version: (.*)/ then fw.firmware = $1 end

		# Process Rules
		if line =~ /^From ([A-Z]+ To [A-Z]+)/ then
			vprint_status("Processing access control list #{$1}.")
			fw.access_lists << Config::AccessList.new($1)
		end
		acl = fw.access_lists.last
		if line =~ /^Rule ([0-9]+) \(([a-zA-z]+)\)/
			vprint_status("Processing rule #{$1}.")
			rule = Config::Rule.new($1)
			if $2 == "Enabled" then rule.enabled = true end
			acl.ruleset << rule
		end
		if acl then rule = acl.ruleset.last end
		if line =~ /^source:\s+(.*)$/
			rule.source = $1
		end
		if line =~ /^destination:\s(.*)$/
			rule.dest = $1
		end
		if line =~ /^action:\s+(.*), service:\s+(.*)/ then
			rule.action = $1
			rule.service = $2
		end

		# Find all interfaces
		if line =~ /^Interface Name:\s+([A-Z0-9]+)/ then
			vprint_status("Processing interface #{$1}.")
			fw.interfaces << Config::Interface.new($1)
		end

		interface = fw.interfaces.last
		if line =~ /^IP Address:\s+(.*)/
			fw.interfaces.last.ip = $1
		end

		if line =~ /^Network Mask:\s+(.*)/
			fw.interfaces.last.mask = $1
		end

		if line =~ /^Port Status:\s+(.*)/
			fw.interfaces.last.status = $1
		end

		if line =~ /^Zone:\s+WAN\s+Handle:.*$/
			fw.interfaces.last.external = true
		end

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

		# Parse Address Object Table
		if line =~ /^(.*): Handle:\d+ ZoneHandle:/
			address_object = true
			service_object = false
		end

		# Parse Service Object Table
		if line =~ /^(.*): Handle:\d+ Size:.* GROUP:/
			name = $1
			address_object = false
			service_object = true
			fw.service_names << Config::ServiceName.new(name)
		end

		if line =~ /^   member: Name:(.*) Handle:\d+/
			if service_object
				fw.service_names.last.ports << port_names[$1]
			end
			if address_object
			end
		end

	end

	return fw
end	

def preprocess_port_names(config)

	port_names = {}

	config.each_line do |line|
		line.chomp!
		if line =~ /^(.*): Handle:\d+ .* IpType:.*/
			name = $1
			puts line
			protocol, port_begin, port_end = parse_port_object(line)
			#puts "#{protocol} #{port_begin} #{port_end}"
			if port_begin == port_end
				port_names[name] = "#{protocol} #{port_begin}"
			else
				port_names[name] = "#{protocol} range #{port_begin} #{port_end}"
			end
		end

	end

	return port_names
end

def parse_port_object(line)
	#port_begin = 'pb'
	#port_end = 'pe'
	#protocol = 'pr'
	line =~ /Port Begin: (\d+)/
	port_begin = $1
	line =~ /Port End: (\d+)/
	port_end = $1
	line =~ /IpType: (\d+)/
	if $1 == '6'
		protocol = 'tcp'
	elsif $1 == '17'
		protocol = 'udp'
	else
		protocol = 'ip_type ' + $1
	end

	puts "protocol: " + protocol
	puts "port_begin: " + port_begin
	puts "port_end: " + port_end
	
	return protocol, port_begin, port_end
end

