require 'analyze/analyze'

def analyze_firewall(firewall)
	print_status("Analyzing firewall configuration.")
	analysis = {}

	# Run checks on firewall configuration
	vprint_status("Checking firewall version.")
	analysis["version"] = check_version(firewall)
	
	vprint_status("Checking firewall rules.")
	analysis["rules"] = check_rules(firewall)

	vprint_status("Checking remote administration.")
	analysis["remote_admin"] = check_remote_admin(firewall)
	
	vprint_status("Checking SNMP configuration.")
	analysis["snmp"] = check_snmp(firewall)

	return analysis
end
