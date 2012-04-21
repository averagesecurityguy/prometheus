##
# Input: A list of Config::AccessList objects
#
# Output: A list of vulnerabilty objects.
#
# Action: The rules in each Config::AccessList object is analyzed for excessive  
# permissions. The source, destination, and service are checked for the 'Any'  
# permission. The more 'Any' permissions, the higher the severity of the 
# vulnerability.
#
def analyze_firewall_rules(acls)

	vulns = []
	high = []
	medium = []
	low = []

	acls.each do |acl|
		acl.ruleset.each do |rule|
			score = 0
			if (rule.enabled? && rule.action == 'Allow')
				if rule.source == 'Any' then score += 1 end
				if rule.dest == 'Any' then score += 1 end
				if rule.service == 'Any' then score += 1 end
			end
			if score == 3 then high << [acl.name, rule.num, rule.source, 
												rule.dest, rule.service] end
			if score == 2 then medium << [acl.name, rule.num, rule.source, 
												rule.dest, rule.service] end
			if score == 1 then low << [acl.name, rule.num, rule.source, 
												rule.dest, rule.service] end
		end
	end

	vprint_status("Analyzing rules for high-severity vulnerabilities.")
	vulns << create_vulnerability('high', high)

	vprint_status("Analyzing rules for medium-severity vulnerabilities.")
	vulns << create_vulnerability('medium', medium)

	vprint_status("Analyzing rules for low-severity vulnerabilities.")
	vulns << create_vulnerability('low', low)

	return vulns
end


##
# Input: A severity rating and a list of affected rules.
#
# Output: An Analysis::Vulnerability object.
#
# Action: Create an Analysis::Vulnerability object with a description based on 
# the severity rating.
def create_vulnerability(sev, affected)

	vuln = nil
	unless affected.empty?
		vuln = Analysis::Vulnerability.new("Overly Permissive Rules")

		vuln.severity = sev

		vuln.desc =  "The following rules have #{sev}-severity vulnerabilities, "
		vuln.desc << "which means traffic is "

		case sev
		when "high"
			vuln.desc << "completely unrestricted because the source, destination, "
			vuln.desc << "and service are set to 'Any'."
		when "medium"
			vuln.desc << "mostly unrestricted because at least two of either the "
			vuln.desc << "source, destination, or service is set to 'Any'."
		when "low"
			vuln.desc << "only somewhat restricted because one of either the "
			vuln.desc << "source, destination, or service is set to 'Any'."
		end

		vuln.solution =  "Rules that make use of 'Any' in the source, "
		vuln.solution << "destination, or service are typically not sufficiently "
		vuln.solution << "restrictive and should be reviewed to ensure they are "
		vuln.solution << "only as permissive as necessary."
	
		cols = ['Access List', 'Rule #', 'Source', 'Destination', 'Service']
		vuln.affected = [cols].concat(affected)
	end

	return vuln
end
