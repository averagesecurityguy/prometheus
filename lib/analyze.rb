require 'analyze/rules'
require 'analyze/remote_admin'

##
# Takes in a Config::Firewall object and returns a list of
# Analyze::Vulnerability objects. Calls each firewall check and concats the
# list of vulnerabilities identified by the check to the master list of
# vulnerabilities.

def analyze_firewall(firewall)
	print_status("Analyzing firewall configuration.")

	vulns = []
	
	# Run checks on firewall rules
	print_status("Checking firewall rules.")
	vulns.concat(analyze_firewall_rules(firewall))

	# Run checks on remote administration
	print_status("Checking remote administration.")
	vulns.concat(analyze_remote_administration(firewall))

	# Analysis is a Hash with vulnerability lists keyed on severity
	highs, meds, lows = split_by_severity(vulns)

	# analysis is an Analysis::Summary object that holds the list of high, med 
	# and low vulnerabilities along with the count of vulnerabilities.
	analysis = Analysis::Summary.new(highs, meds, lows)

	return analysis
end

def split_by_severity(vulns)

	high = []
	med = []
	low = []

	vulns.each do |v|
		if v
			if v.severity == 'high' then high << v end
			if v.severity == 'medium' then med << v end
			if v.severity == 'low' then low << v end
		end
	end

	return high, med, low
end
