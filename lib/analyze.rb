require 'analyze/rules'
require 'analyze/remote_admin'

##
# Takes in a Config::Firewall object and returns a list of
# Analyze::Vulnerability objects. Calls each firewall check and concats the
# list of vulnerabilities identified by the check to the master list of
# vulnerabilities.

def analyze_firewall(firewall)
	print_status("Analyzing firewall configuration.")
	analysis = []

	# Run checks on firewall rules
	print_status("Checking firewall rules.")
	analysis.concat(analyze_firewall_rules(firewall))

	# Run checks on remote administration
	print_status("Checking remote administration.")
	analysis.concat(analyze_remote_administration(firewall))

	return analysis
end
