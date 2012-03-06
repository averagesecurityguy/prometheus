def parse_asa_config(config)

	fw = FirewallConfig.new
	fw.type = "ASA"

	config.each_line do |line|
		if line =~ /^hostname (.*)$/ then fw.id = $1  end
		if line =~ /ASA Version (.*)$/ then fw.firmware = $1 end
		
		# Build interface list
		if line =~ /^interface (.*)/ then fw.interfaces << Interface.new($1) end
		# Rename interface if nameif is defined
		if line =~ /nameif ([a-zA-Z0-9\/]+)/ then
			fw.interfaces.last.name = $1
		end
		if line =~ /^ ip address (.*)/
			ip, mask = $1.split(" ")
			fw.interfaces.last.ip = ip
			fw.interfaces.last.mask = mask
		end
  
		# Build Access list
 		if line =~ /access-list (.*) extended (.*)/ then
			if fw.access_lists.last == nil
				fw.access_lists << AccessList.new($1)
				fw.access_lists.last.ruleset << parse_rule(1, $2)
			elsif fw.access_lists.last.name != $1
				fw.access_lists << AccessList.new($1)
				fw.access_lists.last.ruleset << parse_rule(1, $2)
			else
				id = fw.access_lists.last.ruleset.last.id + 1
				fw.access_lists.last.ruleset << parse_rule(id, $2)
			end
		end

		# Access Groups
		if line =~ /^access-group (.*)/
			name, dir, int, int_name = $1.split(" ")
			fw.access_lists.each do |al|
				if al.name == name then al.interface = int_name end
			end
		end

		# SNMP Configuration


		# Management Interfaces
		if line =~ /http .*\s.*\s(.*)/ then
			vprint_status line
			fw.interfaces.each do |int|
				if int.name == $1 then int.http = true end
			end
		end

		if line =~ /ssh .*\s.*\s(.*)/ then
			vprint_status line
			fw.interfaces.each do |int|
				if int.name == $1 then int.ssh = true end
			end
		end

		if line =~ /telnet .*\s.*\s(.*)/ then
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


def parse_rule(id, rule)
	rule_array = rule.split(" ")
	action = rule_array.shift
	protocol, rule_array = parse_rule_protocol(rule_array)
	source, rule_array = parse_rule_host(rule_array)
	dest, rule_array = parse_rule_host(rule_array)
	service = parse_rule_service(rule_array)

	return Rule.new(id, true, protocol, source, dest, action, service)
  
end

