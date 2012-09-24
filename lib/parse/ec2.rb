##
# Input: A plain-text EC2 Security Group file obtained using ec2-describe-group -H
#
# Output: A FWConfig::FirewallConfig object
#
# Action: Parse the config line by line and update the appropriate parts of 
# the FWConfig::Firewall object
def parse_ec2_config(config)

	fw = FWConfig::FirewallConfig.new

	##
	# Read through each line of the configuration file, use regex to identify 
	# the relevant parts of the config file, and update the FWConfig::Firewall 
	# object as necessary.
	config.each_line do |line|
		rule_count = 0

		line.chomp!
		next if line =~ /^GROUP\sId\sOwner\sName\sDescription\sVpcID$/

		# EC2 security group file does not have a host name associated
		# associated with it.
		if line =~ /^GROUP/
			fw.name = line.split("\t")[2]
			print_debug("Processing firewall #{fw.name}")
		end
		fw.type = 'EC2'

		# Build a list of AccessList objects. EC2 access lists have both 
		# a name and an ID. We will collect both for the access-list name
 		if line =~ /^GROUP/ then
			arr = line.split("\t")
			id = arr[1]
			name = arr[3]

			vprint_status("Processing access control list.")
			print_debug("Name: #{name} \(#{id}\)")
			fw.access_lists << FWConfig::AccessList.new("#{name} (#{id})")

			# Reset the rule count when we get to a new group (access_list)
			rule_count = 0
		end

		if line =~ /^PERMISSION/
			vprint_status("Processing rule")
			rule_count += 1
			arr = line.split("\t")
			print_debug("Rule: #{arr.join("::")}")
			rule = FWConfig::Rule.new(rule_count)
			rule.enabled = true
			rule.protocol = arr[4]

			# Set the action
			if arr[3] == 'ALLOWS'
				rule.action = 'Allow'
			else
				rule.action = 'Deny'
			end
			
			# Set rule source and destination
			if arr[8] == 'USER'
				print_debug("Source: #{arr[8,4].join(" ")}")
				rule.source = arr[8,4].join(" ")
				print_debug("Destination: #{arr[12]}")
				rule.dest = arr[12]
			elsif arr[8] == 'CIDR'
				print_debug("Source: #{arr[9]}")
				rule.source = arr[9]
				print_debug("Destination: #{arr[10]}")
				rule.dest = arr[10]
			end

			# Set rule service
			vprint_status("Processing service.")
			print_debug("Begin Port: #{arr[5]}")
			print_debug("End Port: #{arr[6]}")

			if arr[5] == arr[6]
				rule.service = arr[5]
			elsif ((arr[5] == '0') || (arr[6] == '65535'))
				rule.service = 'Any'
			else
				rule.service = "Range #{arr[5]} #{arr[6]}"
			end
			
			fw.access_lists.last.ruleset << rule

		end

	end

	return fw 
end

