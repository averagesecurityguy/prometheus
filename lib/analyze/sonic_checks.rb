##
# Wrapper function to call each of the cisco checks.
def analyze_sonic_firewall(config)
	vulns =  []

	# vulns.concat()

	return vulns
end

##
# Input: A plain-text firewall config
#
# Output: A list of Analyze::Vulnerability objects
#
# Action: Check for user accounts using type 7 passwords.
#def check_type7(config)
#
#	vprint_status("Checking for type 7 passwords.")
#
#	vulns = []
#	affected = []
#	
#	config.each_line do |line|
#		if line =~ /password 7 (.*)$/ 
#			affected.concat($1)
#		end
#	end
#
#	vulns.append(type7_vulnerability(affected))
#	return vulns
#
#end

##
# Input: A list of affected users.
#
# Output: An Analyze::Vulnerability object.
#
# Action: Create an Analyze::Vulnerability object with the list of usernames.
#def type7_vulnerability(affected)
#	
#	vuln = nil
#
#	if not affected.empty?
#		vuln = Analysis::Vulnerability.new("Cisco Type 7 Passwords")
#		vuln.severity = 'high'
#
#		vuln.desc =  "The following users have type 7 passwords, which are "
#		vuln.desc << "trivial to decode."
#	
#		vuln.solution =  "Configure each user to use a type 5 password using "
#		vuln.solution << "command username <name> secret 0 password. "
#
#		# Add column names to the list of affected interfaces.
#		vuln.affected = [['User Name']].concat(affected)
#	end
#
#	return vuln
#end