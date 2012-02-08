require 'analyze/version'
require 'analyze/rules'
require 'analyze/remote_admin'
require 'analyze/snmp'

def analyze_firewall(firewall)
	analysis = {}

	# Run checks on firewall configuration
	analysis["version"] = Analyze::check_version(firewall)
	analysis["rules"] = Analyze::check_rules(firewall)
	analysis["remote_admin"] = Analyze::check_remote_admin(firewall)
	analysis["snmp"] = Analyze::check_snmp(firewall)

	return analysis
end
