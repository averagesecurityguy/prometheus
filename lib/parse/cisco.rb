module Parse

include Config

def parse_cisco_config(config)

	firewall = FirewallConfig.new

	config.each_line do |line|
		if line =~ /^hostname (.*)$/ then firewall.id = $1  end
		if line =~ /^ASA Version (.*)$/ then firewall.firmware = $1 end
		if line =~ /^: Written by (.*) at (.*)/ then
			time, zone, weekday, month, day, year = $2.split(" ")
			firewall.date = "#{month}/#{day}/#{year}"
		end

		#Build interface list
		if line =~ /^interface (.*)/ then firewall.interfaces << Interface.new($1) end
		if line =~ /^ ip address (.*)/
			ip, mask = $1.split(" ")
			firewall.interfaces.last.ip = ip
			firewall.interfaces.last.mask = mask
		end
  
		#Build Access list
 		if line =~ /access-list (.*) extended (.*)/ then
			if firewall.access_lists.last == nil
				id = 1
				firewall.access_lists << AccessList.new($1)
				firewall.access_lists.last.ruleset << parse_rule($2)
			elsif firewall.access_lists.last.name != $1
				id = 1
				firewall.access_lists << AccessList.new($1)
				firewall.access_lists.last.ruleset << parse_rule($2)
			else
				id += 1
				firewall.access_lists.last.ruleset << parse_rule($2)
			end
		end

		#Access Groups
		if line =~ /access-group (.*)/
			name, dir, int, int_name = $1.split(" ")
			firewall.access_lists.each do |al|
				if al.name == name then al.interface = int_name end
			end
		end
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
    end
end


def parse_rule(id, rule)

	rule_array = rule.split(" ")
	action = rule_array.shift
	protocol = rule_array.shift
	source, rule_array = parse_rule_host(rule_array)
	dest, rule_array = parse_rule_host(rule_array)
	service = parse_rule_service(rule_array)

	return Rule.new(id, true, source, dest, action, service)
  
end

end
