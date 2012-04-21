#-----------------------------------------------------------------------------
# This module is used to call each of the firewall checks. The code for each
# check should be in a separate ruby file within the lib/analyze folder and
# should be 'required' below. Each check is expected to take as its input all 
# or part of a Config::Firewall object and should return a list of 
# Analyze::Vulnerability objects, which will be added to the master list and 
# then separated by severity.
#-----------------------------------------------------------------------------

require 'analyze/rules'
require 'analyze/remote_admin'


##
# Input: A populated Config::Firewall object.
#
# Output: Three lists of Analyze::Vulnerability objects, corresponding to the 
# severity levels high, medium, and low.
#
# Action: Calls each firewall check and concatenates the list of 
# vulnerabilities identified by each check into a master list of 
# vulnerabilities. The master list is then separated into three lists, which 
# are used to populate an Analyze::Summary object.
def analyze_firewall(firewall)
	print_status("Analyzing firewall configuration.")

	vulns = []
	
	# Run checks on firewall rules
	print_status("Checking firewall rules.")
	vulns.concat(analyze_firewall_rules(firewall.access_lists))

	# Run checks on remote administration
	print_status("Checking remote administration.")
	vulns.concat(analyze_remote_administration(firewall.interfaces))

	# Analysis is a Hash with vulnerability lists keyed on severity
	highs, meds, lows = split_by_severity(vulns)

	# analysis is an Analysis::Summary object that holds the list of high, med 
	# and low vulnerabilities along with the count of vulnerabilities.
	analysis = Analysis::Summary.new(highs, meds, lows)

	return analysis
end


##
# Input: A list of Analyze::Vulnerability objects
#
# Output: Three lists of Analyze::Vulnerability objects
#
# Action: Separates a list of Analyze::Vulnerability objects based on severity.
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
