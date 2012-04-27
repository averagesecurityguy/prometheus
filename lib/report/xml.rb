#-------------------------------------------------------------------------
# Professional Functionality
#-------------------------------------------------------------------------

module Report
module XMLReport
	require 'date'

	##
	# Input: Config::Firewall object and an Analysis::Summary object. 
	#
	# Output: A string containing an XML representation of the report.
	#
	# Action: Create an XML document using the data in the Config::Firewall 
	# object and the Analysis::Summary object.
	def generate_xml_report(firewall, analysis)
		vprint_status("Writing XML report.")
		xml =  "<Prometheus version=\"1.0\">\n"

		# Add configuration information to XML
		xml << "<configuration>\n"
		xml << create_element('name', firewall.name) + "\n"
		xml << create_element('type', firewall.type) + "\n"
		xml << create_element('firmware', firewall.firmware) + "\n"

		# Add configuration summary information to XML
		xml << "<summary>"
		xml << create_element('rule_count', firewall.rule_count)
		xml << create_element('acl_count', firewall.acl_count)
		xml << create_element('interface_count', firewall.int_count)
		xml << create_element('interface_up_count', firewall.ints_up)
		xml << "</summary>"
		
		# Add interfaces to XML
		xml << interfaces_to_xml(firewall.interfaces)

		# Add access control lists to XML
		xml << access_lists_to_xml(firewall.access_lists, firewall.type)

		# Add host names to xml
		xml << host_names_to_xml(firewall.host_names)

		# Add network names to XML
		xml << network_names_to_xml(firewall.network_names)

		# Add service names to XML
		xml << service_names_to_xml(firewall.service_names)

		xml << "</configuration>\n"
	
		# Add Analysis results
		xml << "<analysis>\n"
		
		# Add analysis summary information to XML
		x = "<summary>"
		x = create_element('high_count', analysis.high_count)
		x = create_element('medium_count', analysis.medium_count)
		x = create_element('low_count', analysis.low_count)
		x = create_element('high_rule_count', analysis.high_rule_count)
		x = create_element('medium_rule_count', analysis.medium_rule_count)
		x = create_element('low_rule_count', analysis.low_rule_count)
		x = "</summary>"

		# Add vulnerabilities to XML
		xml << vulnerabilities_to_xml(analysis)

		xml << "</analysis>\n"
		xml << "</Prometheus>\n"

	   	return xml

	end

	##
	# Create an XML element with the name and text.
	def create_element(name, text)
		return "<#{name}>#{text}</#{name}>"
	end

	##
	# Convert the interface list to XML
	def interfaces_to_xml(interfaces)
		vprint_status("Writing interfaces to XML.")

		x = ''
		if interfaces

			x << "<interfaces>\n"

			interfaces.each do |i|
				x << "<interface>"
				x << create_element('name', i.name)
				x << create_element('ip', i.ip)
				x << create_element('mask', i.mask)
				x << create_element('status', i.status)
				x << create_element('http', i.http)
				x << create_element('https', i.https)
				x << create_element('ssh', i.ssh)
				x << create_element('telnet', i.telnet)
				x << "</interface>\n"
			end

			x << "</interfaces>\n"

		end

		return x

	end

	##
	# Convert the access_lists to XML
	def access_lists_to_xml(acls, type)
		vprint_status("Writing access control lists to XML.")
		x = ''

		if acls
			x << "<access_lists>\n"

			acls.each do |a|
				x << "<access_list>"
				x << create_element('name', a.name)
				x << create_element('interface', a.interface ? a.interface : '')
				x << "<rules>"
				a.ruleset.each do |r|
					x << rule_to_xml(r, type)
				end
				x << "</rules>"
				x << "</access_list>\n"
			end

			x << "</access_lists>\n"
		end

		return x
	end

	##
	# Convert a rule to XML
	def rule_to_xml(rule, type)
		vprint_status("Writing rule to XML")

		x =  ''
		x << '<rule>'
		x << create_element('id', rule.num)
		x << create_element('enabled', rule.enabled)
		x << create_element('protocol', rule.protocol)
		x << create_element('source', rule.source)
		x << create_element('destination', rule.dest)
		x << create_element('action', rule.action)
		x << create_element('service', rule.service)
		x << create_element('comment', rule.comment)
		x << '</rule>'

		return x
	end


	##
	# Convert the vulnerabilities to XML. Write out each group of 
	# vunerabilities separately.
	def vulnerabilities_to_xml(analysis)
		vprint_status("Writing vulnerabilities to XML.")
		x = "<vulnerabilities>\n"

		# Add high severity vulnerabilities
		x << "<high_severity>\n"
		unless analysis.highs.empty?
			x << vuln_list_to_xml(analysis.highs)
		else
			x << ""
		end
		x << "</high_severity>\n"

		# Add medium severity vulnerabilities
		x << "<medium_severity>\n"
		unless analysis.mediums.empty?
			x << vuln_list_to_xml(analysis.mediums)
		else
			x << ""
		end
		x << "</medium_severity>\n"

		# Add low severity vulnerabilities
		x << "<low_severity>\n"
		unless analysis.lows.empty?
			x << vuln_list_to_xml(analysis.lows)
		else
			x << ""
		end
		x << "</low_severity>\n"

		x << "</vulnerabilities>\n"
		return x
	end

	##
	# Wrapper method to write a list of vulnerabilities to XML
	def vuln_list_to_xml(vulns)

		x = ''

		vulns.each do |v|
			x << vulnerability_to_xml(v)
		end

		return x
	end

	##
	# Convert an individual vulnerability to XML
	def vulnerability_to_xml(v)
		vprint_status("Writing #{v.name} (#{v.severity.upcase}) to XML.")
		x = ''

		x << "<vulnerability>"
		x << create_element('name', v.name)
		x << create_element('severity', v.severity)
		x << create_element('description', v.desc)
		x << create_element('solution', v.solution)
		x << "<affected_items_table>"

		x << create_element('affected_item_header', v.affected[0].join(","))

		v.affected[1, v.affected.length].each do |a|
			x << create_element('affected_item_row', a.join(","))
		end
 
		x << "</affected_items_table>"
		x << "</vulnerability>\n"

		return x
	end

	##
	# Convert host_names to XML
	def host_names_to_xml(host_names)
		vprint_status("Writing host names to XML.")
		x = ''

		unless host_names.empty?
			x << "<host_names>\n"	
			
			host_names.each do |name, ip|
				x << '<host_name>'
				x << create_element('name', name)
				x << create_element('ip', ip)
				x << "</host_name>\n"
			end

			x << "</host_names>\n"
		end

		return x
	end

	##
	# Convert network_names to XML
	def network_names_to_xml(network_names)
		vprint_status("Writing network names to XML.")
		x = ''

		unless network_names.empty?
			x << "<network_names>\n"

			network_names.each do |n|
				x << "<network_name>"
				x << create_element('name', n.name)
				x << "<hosts>"

				n.hosts.each do |host|
					x << create_element('host', host)
				end

				x << "</hosts>"
				x << "</network_name>\n"
			end

			x << "</network_names>\n"

		end

		return x
	end


	##
	# Convert Service Names to XML
	def service_names_to_xml(service_names)
		vprint_status("Writing service names to XML.")
		x = ''

		unless service_names.empty?
			x << "<service_names>\n"

			service_names.each do |s|
				x << "<service_name>"
				x << create_element('name', s.name)
				x << create_element('protocol', s.protocol)
				x << "<ports>"

				s.ports.each do |p|
					x << create_element('port', p)
				end

				x << "</ports>"
				x << "</service_name>\n" 
			end

			x << "</service_names>\n"
		end

		return x
	end


end

end
