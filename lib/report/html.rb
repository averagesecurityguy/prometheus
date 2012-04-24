module Report
module HTMLReport
	require 'date'

	def generate_html_report(firewall, analysis, template)

		# Open template file
		if not File.exists?(template)
			raise ReportError, "File #{template} does not exist."
		end

		if not File.file?(template)
			raise ReportError, "#{template} is not a file."
		end

		if File.zero?(template)
			raise ReportError, "The file #{template} is empty."
		end

		html = File.open(template) {|f| f.read}

		# Replace id, firmware, and type
		html.gsub!(/--name--/, firewall.name)
		html.gsub!(/--type--/, firewall.type)
		html.gsub!(/--firmware--/, firewall.firmware)

		# Insert Summary Statement
		html.gsub!(/--summary_statement--/, summary_to_html(firewall, analysis))

		# Insert Interfaces
		html.gsub!(/--interfaces--/, interfaces_to_html(firewall.interfaces))

		# Insert Remote Management
		html.gsub!(/--management--/, management_to_html(firewall.interfaces))

		# Insert Access Control Lists
		html.gsub!(/--access_lists--/, access_lists_to_html(firewall.access_lists))

		# Insert Analysis Results
		html.gsub!(/--analysis--/, vulnerabilities_to_html(analysis))

		# Insert Host Names
		html.gsub!(/--host_names--/, host_names_to_html(firewall.host_names))

		# Insert Network Names
		html.gsub!(/--network_names--/, network_names_to_html(firewall.network_names))

		# Insert Analysis Results
		html.gsub!(/--service_names--/, service_names_to_html(firewall.service_names))

	   	return html

	end

	def summary_to_html(fw, an)
	
		summary =  "<div id=\"summary_statement\">\n"
		summary << "<p>The #{fw.type} firewall with hostname <em>#{fw.name}</em> "
		summary << "and running firmware version <em>#{fw.firmware}</em> was "
		summary << "analyzed with Prometheus Firewall Analyzer (Prometheus) on "
		summary << "#{Date.today.to_s}. Prometheus identified (#{an.high_count}) "
		summary << "high-severity, (#{an.medium_count}) medium-severity, and "
		summary << "(#{an.low_count}) low-severity vulnerabilities.</p>"
		summary << "Prometheus identified #{fw.int_count} interfaces on the "
		summary << "firewall, #{fw.ints_up} of which were active.</p>"
		summary << "Prometheus processed #{fw.acl_count} access control lists "
		summary << "with a total of #{fw.rule_count} rules. Of the #{fw.rule_count} "
		summary << "rules identified, #{an.high_rule_count} were high-severity "
		summary << "rules, #{an.medium_rule_count} were medium-severity rules, and "
		summary << "#{an.low_rule_count} were low_severity rules.</p>"
		summary << "</div>\n"

		return summary
	end

	##
	# Convert the interface list to HTML
	def interfaces_to_html(interfaces)
		vprint_status("Writing interfaces to HTML.")

		h = ''
		if interfaces

			h << "<div id=\"interfaces\">\n"
			h << "<h3>Interfaces</h3>\n"

			t = HTMLTable::Table.new( 
				'Columns' => ['Name', 'IP Address', 'Subnet Mask', 'Status']
			)

			interfaces.each do |i|
				t.rows << [i.name, i.ip, i.mask, i.status]
			end

			h << t.to_html
			h << "<div>\n"
		end

		return h

	end

	##
	# Convert the management interfaces to HTML
	def management_to_html(interfaces)
		vprint_status("Writing remote management to HTML.")
		h = ''

		if interfaces
			h << "<div id=\"remote_management\">\n"
			h << "<h3>Remote Management</h3>\n"

			t = HTMLTable::Table.new(
				'Columns' => ['Interface', 'HTTP', 'HTTPS', 'SSH', 'Telnet']
			)

			interfaces.each do |i|
				t.rows << [i.name, i.http, i.https, i.ssh, i.telnet]
			end

			h << t.to_html
			h << "</div>\n"
		end

		return h
	end

	##
	# Convert the vulnerabilities to HTML 
	def vulnerabilities_to_html(analysis)
		vprint_status("Writing vulnerabilities to HTML.")
		h = "<div id=\"vulnerabilities\">\n"

		h << "<h3>High-severity Vulnerabilities</h3>\n"
		unless analysis.highs.empty?
			h << vuln_list_to_html(analysis.highs)
		else
			h << "<p>No high-severity vulnerabilities to report.</p>\n"
		end

		h << "<h3>Medium-severity Vulnerabilities</h3>\n"
		unless analysis.mediums.empty?
			h << vuln_list_to_html(analysis.mediums)
		else
			h << "<p>No medium-severity vulnerabilities to report.</p>\n"
		end

		h << "<h3>Low-severity Vulnerabilities</h3>\n"
		unless analysis.lows.empty?
			h << vuln_list_to_html(analysis.lows)
		else
			h << "<p>No low-severity vulnerabilities to report.</p>\n"
		end

		h << "</div>\n"
		return h
	end

	def vuln_list_to_html(vulns)

		h = ''

		vulns.each do |v|
			h << vulnerability_to_html(v)
		end

		return h
	end

	##
	# Convert an individual vulnerability to HTML
	def vulnerability_to_html(v)
		vprint_status("Writing #{v.name} (#{v.severity.upcase}) to HTML.")
		h = ''

		t = HTMLTable::Table.new( 'Columns' => v.affected[0])

		v.affected[1, v.affected.length].each do |a|
			t.rows << a
		end

		h << "<div>\n"
		h << "<h4>#{v.name} (#{v.severity.upcase})</h4>\n"
		h << "<p><strong>Description:</strong> #{v.desc}</p>\n"
		h << "<p><strong>Solution:</strong> #{v.solution}</p>\n"
		h << t.to_html
		h << "</div>\n"

		return h
	end

	def access_lists_to_html(acls)
		vprint_status("Writing access control lists to HTML.")
		h = ''

		if acls
			h << "<div id=\"access_lists\">\n"
			h << "<h3>Access Control Lists</h3>\n"
			acls.each do |a|
				interface = a.interface ? " (#{a.interface})" : ''
				t = HTMLTable::Table.new(
					'Columns' => ['ID', 'Enabled', 'Protocol', 'Source', 'Destination', 'Action', 'Service'],
					'Header' => a.name + interface
				)
				a.ruleset.each do |r|
					t.rows << [r.num, r.enabled, r.protocol, r.source, r.dest, r.action, r.service]
				end

				h << t.to_html
			end

			h << "</div>\n"
		end

		return h
	end

	def host_names_to_html(host_names)
		vprint_status("Writing host names to HTML.")
		h = ''

		unless host_names.empty?
			h << "<div id=\"host_names\">\n"	
			h << "<h3>Host Names</h3>\n"

			t = HTMLTable::Table.new(
				'Columns' => ['Host Name', 'IP Address']
			)

			host_names.each do |name, ip|
				t.rows << [name, ip]
			end

			h << t.to_html
			h << "</div>\n"
		end

		return h
	end

	def network_names_to_html(network_names)
		vprint_status("Writing network names to HTML.")
		h = ''

		unless network_names.empty?
			h << "<div id=\"network_names\">\n"
			h << "<h3>Network Names</h3>\n"

			network_names.each do |n|
				t = HTMLTable::Table.new(
					'Header' => n.name, 
					'Columns' => ['Hosts']
				)
				n.hosts.each do |host|
					t.rows << [host]
				end
				h << t.to_html
			end

			h << "</div>\n"

		end

		return h
	end

	def service_names_to_html(service_names)
		vprint_status("Writing service names to HTML.")
		h = ''

		unless service_names.empty?
			h << "<div id=\"service_names\">\n"
			h << "<h3>Service Names</h3>\n"

			service_names.each do |s|
				p s
				t = HTMLTable::Table.new(
					'Header' => "#{s.name} (#{s.protocol})",
					'Columns' => ['Ports']
				)

				s.ports.each do |p|
					t.rows << [p]
				end
				h << t.to_html
			end

			h << "</div>\n"
		end

		return h
	end


end

end
