def parse_sonic_config(config)

	fw = Config::FirewallConfig.new
	fw.type = "SonicOS"

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
			if $2 == "Enabled" then rule.enabled = "Yes" end
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
		if line =~ /^Interface http Management:\s+(.*)/
			fw.interfaces.last.http = $1
		end
		if line =~ /^Interface https Management:\s+(.*)/
			fw.interfaces.last.https = $1
		end
		if line =~ /^Interface ssh Management:\s+(.*)/
			fw.interfaces.last.ssh = $1
		end

	end

	return fw
end	

