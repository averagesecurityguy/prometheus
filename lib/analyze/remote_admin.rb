##
# Wrapper function to call each of the remote administration checks. Keeps the 
# analyze.rb code cleaner to do multiple calls in a wrapper function.
def analyze_remote_administration(interfaces)
	vulns =  []

	vulns.concat(check_cleartext_administration(interfaces))
	vulns.concat(check_external_administration(interfaces))

	return vulns
end

##
# Input: A list of Config::Interface objects
#
# Output: A list of Analyze::Vulnerability objects
#
# Action: Loop through each interface and see if either HTTP or Telnet is used 
# for remote administration. If either is in use then create a vulnerability.
def check_cleartext_administration(ints)

	vprint_status("Checking for cleartext administration.")

	vulns = []
	http = []
	telnet = []

	ints.each do |int|
		if int.http? then http << [int.name] end
		if int.telnet? then telnet << [int.name] end
	end

	vuln = rm_cleartext_vulnerability('HTTP', http)
	if vuln then vulns << vuln end

	vuln = rm_cleartext_vulnerability('Telnet', telnet)
	if vuln then vulns << vuln end

	return vulns

end

##
# Input: A list of Config::Interface objects
#
# Output: A list of Analyze::Vulnerability objects
#
# Action: Loop through each interface. If the interface is labled as an 
# external interface and either of the remote administration protocols are in
# use on the interface then create a vulnerability.
def check_external_administration(ints)
	vprint_status("Checking for external administration.")

	vulns = []
	external = []

	ints.each do |int|
		eadmin = false
		if int.external?
			vprint_status("External Check: #{int.name}")
			if int.http? then eadmin = true end
			if int.https? then eadmin = true end
			if int.ssh? then eadmin = true end
			if int.telnet? then eadmin = true end
		end
		if eadmin then external << [int.name] end
	end

	vuln = rm_external_vulnerability(external)
	if vuln then vulns << vuln end

	return vulns

end

##
# Input: A protocol name and a list of affected interface names.
#
# Output: An Analyze::Vulnerability object.
#
# Action: Create an Analyze::Vulnerability object and vary the description and 
# solution based on the protocol
def rm_cleartext_vulnerability(proto, affected)
	
	vuln = nil

	if not affected.empty?
		vuln = Analysis::Vulnerability.new("Remote Management with #{proto}")
		vuln.severity = 'high'

		vuln.desc =  "The following interfaces are using #{proto} for remote "
		vuln.desc << "administration. #{proto} is considered insecure because all "
		vuln.desc << "information is transmitted in clear text, which could "
		vuln.desc << "allow an attacker to capture login credentials."
	
		vuln.solution =  "Disable remote management through #{proto}, if possible. "
		vuln.solution << "If it is not possible, limit access to the management "
		vuln.solution << "interface to only those IP addresses necessary."

		# Add column names to the list of affected interfaces.
		vuln.affected = [['Interface']].concat(affected)
	end

	return vuln
end

##
# Input: A list of affected interface names.
#
# Output: An Analyze::Vulnerability object.
#
# Action: Create an Analyze::Vulnerabilty object for remote management on 
# external interfaces.
def rm_external_vulnerability(affected)
	
	vuln = nil

	if not affected.empty?
		vuln = Analysis::Vulnerability.new("Remote Management on External Interface")
		vuln.severity = 'high'

		vuln.desc =  "The firewall can be remotely managed on the following "
		vuln.desc << "external interfaces. This gives an external attacker "
		vuln.desc << "the opportunity to exploit any known vulnerabilities in "
		vuln.desc << "the management interface. In addition, an attacker may "
		vuln.desc << "be able to conduct a dictionary password attack on the "
		vuln.desc << "management interface login. A successful attack could "
		vuln.desc << "give the attacker complete control of the firewall."
	
		vuln.solution =  "Disable external remote management, if possible. If "
		vuln.solution << "it is not possible, then limit access to the "
		vuln.solution << "management interface to only those IP addresses "
		vuln.solution << "necessary."

		# Add header to list of affected interfaces
		vuln.affected = [['Interface']].concat(affected)
	end

	return vuln
end

