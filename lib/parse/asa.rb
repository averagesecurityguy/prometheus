def parse_cisco_config(config)

	fw = Config::FirewallConfig.new

	# Both network objects and service objects can contain group objects. This
	# variable is used to determine if we are processing a network object or 
	# not.
	process_network = false

	config.each_line do |line|
		line.chomp!
		if line =~ /^hostname (.*)$/ then fw.name = $1  end

		# Is this an ASA or PIX
		if line =~ /ASA Version (.*)$/
			fw.firmware = $1.rstrip()
			fw.type = 'ASA'
		end

		if line =~ /PIX Version (.*)$/
			fw.firmware = $1
			fw.type = 'PIX'
		end

		# Build named ip address list
		if line =~ /^name (\d+\.\d+.\d+.\d+) (.*)/
			fw.host_names[parse_ip_name($2)] = $1
		end
		
		# Build interface list
		if line =~ /^interface (.*)/ then
			vprint_status("Processing interface #{$1}")
			fw.interfaces << Config::Interface.new($1)
		end
		interface = fw.interfaces.last

		# Rename interface if nameif is defined
		if line =~ /^ nameif ([a-zA-Z0-9\/]+)/ then
			interface.name = $1
		end

		if line =~ /^ ip address (.*)/
			ip, mask = $1.split(" ")
			interface.ip = ip
			interface.mask = mask
		end

		if line =~ /^ shutdown/
			interface.status = "Down"
		end

		if line =~ /^ security-level (\d+)/
			if $1 == 0 then interface.external = true end
		end

		# Build Network Names
		if line =~ /object-group network (.*)/
			vprint_status("Processing network group: " + $1)
			fw.network_names << Config::NetworkName.new($1)
			process_network = true
		end

		if line =~ /^ network-object (.*)/
			vprint_status("Processing network object: " + $1)
			fw.network_names.last.hosts << $1
		end
		
		# if we are processing a network object and we have a group object
		# we add it to the hosts.
		if ((line =~ /^ group-object (.*)/) && (process_network))
			vprint_status("Processing network group-object: " + $1)
			fw.network_names.last.hosts << 'group ' + $1
		end

		# Build Service Names
		if line =~ /object-group service (.*)/
			vprint_status("Processing service group: " + $1)
			name, protocol = parse_service_object($1)
			fw.service_names << Config::ServiceName.new(name)
			fw.service_names.last.protocol = protocol
			process_network = false
		end

		# if we are not processing a network object and we have a group object
		# we add it to the services
		if ((line =~ /^ group-object (.*)/) && (not process_network))
			vprint_status("Processing service group-object: " + $1)
			fw.service_names.last.ports << 'group ' + $1
		end

		if line =~ /^ port-object eq (.*)/
			vprint_status("Processing port: " + $1)
			fw.service_names.last.ports << 'port ' + $1
		end
		
		if line =~ /^ port-object range (.*)/
			vprint_status("Processing port range: " + $1)
			fw.service_names.last.ports << 'range ' + $1
		end

		if line =~ /^ service-object (.*) (range|eq) (.*)/
			vprint_status("Processing service object")
			protocol = $1
			ports = $3
			
			if $2 == 'range'
				fw.service_names.last.ports << "#{protocol} range #{ports}"
			else
				fw.service_names.last.ports << "#{protocol} #{ports}"
			end
		end

		# Build Access list
 		if line =~ /access-list (.*) extended (.*)/ then
			if fw.access_lists.last == nil
				vprint_status("Processing access list: " + $1)
				fw.access_lists << Config::AccessList.new($1)
				fw.access_lists.last.ruleset << parse_rule(1, $2)
			elsif fw.access_lists.last.name != $1
				vprint_status("Processing access list: " + $1)
				fw.access_lists << Config::AccessList.new($1)
				fw.access_lists.last.ruleset << parse_rule(1, $2)
			else
				num = fw.access_lists.last.ruleset.last.num + 1
				fw.access_lists.last.ruleset << parse_rule(num, $2)
			end
		end

		# Access Groups
		if line =~ /^access-group (.*)/
			name, dir, int, int_name = $1.split(" ")
			vprint_status("Processing access-group: " + name)
			fw.access_lists.each do |al|
				if al.name == name then al.interface = int_name end
			end
		end

		# Management Interfaces
		if line =~ /^http .*\s.*\s(.*)/ then
			vprint_status line
			fw.interfaces.each do |int|
				if int.name == $1 then int.http = true end
			end
		end

		if line =~ /^ssh .*\s.*\s(.*)/ then
			vprint_status line
			fw.interfaces.each do |int|
				if int.name == $1 then int.ssh = true end
			end
		end

		if line =~ /^telnet .*\s.*\s(.*)/ then
			vprint_status line
			fw.interfaces.each do |int|
				if int.name == $1 then int.telnet = true end
			end
		end
			
	end

	return fw 
end


def parse_rule_protocol(rule_array)
	prot = rule_array.shift
	case prot
		when "object-group"
			return rule_array.shift, rule_array
		else
			return prot, rule_array
	end
end


def parse_rule_host(rule_array)
	host = rule_array.shift
	case host
		when "any"
			return "0.0.0.0/0", rule_array
		when "host"
			return rule_array.shift + "/32", rule_array
		when "object-group"
			return rule_array.shift, rule_array
		else
			return host + "/" + rule_array.shift, rule_array
	end
end


def parse_rule_service(rule_array)
	srv = rule_array.shift
	case srv
		when nil
			return "any"
		when "eq"
			return rule_array.shift
		when "range"
			return rule_array.shift + " - " + rule_array.shift
		when "object-group"
			return rule_array.shift
		else
			return srv
    end
end


def parse_rule(id, string)
	rule = Config::Rule.new(id)
	rule.enabled = true
	rule_array = string.split(" ")
	rule.action = rule_array.shift
	rule.protocol, rule_array = parse_rule_protocol(rule_array)
	rule.source, rule_array = parse_rule_host(rule_array)
	rule.dest, rule_array = parse_rule_host(rule_array)
	rule.service = parse_rule_service(rule_array)

	return rule
  
end


def parse_ip_name(str)
	ip_name = str
	if str =~ /(.*) description (.*)/
		ip_name = $1
	end

	return ip_name
end

def parse_service_object(str)
	name = protocol = ''
	if str =~ /(.*) (tcp|udp|tcp-udp)$/
		name = $1
		protocol = $2
	else
		name = str
		protocol = 'tcp'
	end

	return name, protocol

end

