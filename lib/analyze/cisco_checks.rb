##
# Wrapper function to call each of the cisco checks.
def analyze_cisco_firewall(config)
	vulns =  []

	vuln = check_type7(config)
	if vuln then vulns.concat(vuln) end

	return vulns
end

##
# Input: A plain-text firewall config
#
# Output: A list of Analyze::Vulnerability objects
#
# Action: Check for user accounts using type 7 passwords.
def check_type7(config)

	vprint_status("Checking for type 7 passwords.")
	
	affected = []
	
	config.each_line do |line|
		if line =~ /password 7 (.*)$/ 
			affected.concat($1)
		end
	end

	vuln = nil
	
	if not affected.empty?
		vuln = Analysis::Vulnerability.new("Cisco Type 7 Passwords")
		vuln.severity = 'high'

		vuln.desc =  "The following users have type 7 passwords, which are "
		vuln.desc << "trivial to decode."
	
		vuln.solution =  "Configure each user to use a type 5 password using "
		vuln.solution << "command username <name> secret 0 password. "

		# Add column names to the list of affected interfaces.
		vuln.affected = [['User Name']].concat(affected)
	end

	return vuln

end