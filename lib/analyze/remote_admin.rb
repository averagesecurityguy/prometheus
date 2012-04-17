def analyze_remote_administration(fw)
	vulns =  []

	vulns.concat(check_cleartext_administration(fw))
	vulns.concat(check_external_administration(fw))

	return vulns
end

def check_cleartext_administration(fw)

	vprint_status("Checking for cleartext administration.")

	vulns = []
	http = []
	telnet = []

	fw.interfaces.each do |i|
		if i.http? then http << [i.name] end
		if i.telnet? then telnet << [i.name] end
	end

	vuln = rm_cleartext_vulnerability('HTTP', http)
	if vuln then vulns << vuln end

	vuln = rm_cleartext_vulnerability('Telnet', telnet)
	if vuln then vulns << vuln end

	return vulns

end

def check_external_administration(fw)
	vprint_status("Checking for external administration.")

	vulns = []
	external = []

	fw.interfaces.each do |i|
		eadmin = false
		if i.external?
			vprint_status("External Check: #{i.name}")
			if i.http? then eadmin = true end
			if i.https? then eadmin = true end
			if i.ssh? then eadmin = true end
			if i.telnet? then eadmin = true end
		end
		if eadmin then external << [i.name] end
	end

	vuln = rm_external_vulnerability(external)
	if vuln then vulns << vuln end

	return vulns

end

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

