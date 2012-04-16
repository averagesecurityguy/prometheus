def analyze_firewall_rules(fw)

	analysis = []
	critical = []
	high = []
	medium = []

	fw.access_lists.each do |al|
		al.ruleset.each do |r|
			score = 0
			if (r.enabled? && r.action == 'Allow')
				if r.source == 'Any' then score += 1 end
				if r.dest == 'Any' then score += 1 end
				if r.service == 'Any' then score += 1 end
			end
			if score == 3 then critical << [al.name, r.num, r.source, r.dest, r.service] end
			if score == 2 then high << [al.name, r.num, r.source, r.dest, r.service] end
			if score == 1 then medium << [al.name, r.num, r.source, r.dest, r.service] end
		end
	end

	vprint_status("Analyzing rules for critical-severity vulnerabilities.")
	vuln = rule_vulnerability('critical', critical)
	if vuln then analysis << vuln end

	vprint_status("Analyzing rules for high-severity vulnerabilities.")
	vuln = rule_vulnerability('high', high)
	if vuln then analysis << vuln end

	vprint_status("Analyzing rules for medium-severity vulnerabilities.")
	vuln = rule_vulnerability('medium', medium)
	if vuln then analysis << vuln end

	return analysis
end

def rule_vulnerability(sev, affected)

	vuln = nil
	if not affected.empty?
		vuln = Vulnerability.new("Rules with #{sev}-severity vulnerabilities")

		vuln.severity = sev

		vuln.desc =  "The following rules have #{sev}-severity vulnerabilities, "
		vuln.desc << "which means traffic is "

		case sev
		when "critical"
			vuln.desc << "completely unrestricted because the source, destination, "
			vuln.desc << "and service are set to 'Any'."
		when "high"
			vuln.desc << "mostly unrestricted because at least two of either the "
			vuln.desc << "source, destination, or service is set to 'Any'."
		when "medium"
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
