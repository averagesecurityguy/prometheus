module Report
module HTMLReport
	require 'date'

	##
	# Input: FWConfig::Firewall object, Analysis::Summary object, and a file name 
	# containing a template for the HTML report. 
	#
	# Output: A string containing an HTML file with the report.
	#
	# Action: Make sure the template file exists, is a file and is not empty. 
	# Open the file and insert the appropriate parts of the report. A custom 
	# template file can be specified using the -t command line option.
	def generate_html_report(firewall, analysis, template)

		# Does the tempate file exist?
		unless File.exists?(template)
			raise ReportError, "File #{template} does not exist."
		end

		# Is the file a file and not a directory?
		unless File.file?(template)
			raise ReportError, "#{template} is not a file."
		end

		# Is the file empty?
		if File.zero?(template)
			raise ReportError, "The file #{template} is empty."
		end

		# Open the template file
		html = File.open(template) {|f| f.read}

		# Replace id, firmware, and type
		html.gsub!(/--name--/, firewall.name)
		html.gsub!(/--type--/, firewall.type)
		html.gsub!(/--firmware--/, firewall.firmware ? firewall.firmware : "None")

		# Insert Summary Statement
		html.gsub!(/--summary_statement--/, summary_to_html(firewall, analysis))

		# Insert Interfaces
		html.gsub!(/--interfaces--/, interfaces_to_html(firewall.interfaces))

		# Insert Remote Management
		html.gsub!(/--management--/, management_to_html(firewall.interfaces))

		# Insert Access Control Lists
		html.gsub!(/--access_lists--/, access_lists_to_html(firewall.access_lists, firewall.type))

		# Insert Analysis Results
		html.gsub!(/--analysis--/, vulnerabilities_to_html(analysis))

		# Insert Host Names
		html.gsub!(/--host_names--/, host_names_to_html(firewall.host_names))

		# Insert Network Names
		html.gsub!(/--network_names--/, network_names_to_html(firewall.network_names))

		# Insert Service Names
		html.gsub!(/--service_names--/, service_names_to_html(firewall.service_names))

	   	return html

	end

	##
	# Input: A FWConfig::Firewall object and an Analysis::Summary object
	#
	# Output: A string containing a summary of the configuration and analysis. 
	def summary_to_html(fw, an)
	
		s =  "<div id=\"summary_statement\">\n"
		s << "<p>The #{fw.type} firewall with hostname <em>#{fw.name}</em> "
		s << "and running firmware version <em>#{fw.firmware}</em> was "
		s << "analyzed with Prometheus Firewall Analyzer (Prometheus) on "
		s << "#{Date.today.to_s}. Prometheus identified (#{an.high_count}) "
		s << "high-severity, (#{an.medium_count}) medium-severity, and "
		s << "(#{an.low_count}) low-severity vulnerabilities.</p>"
		s << "Prometheus processed #{fw.acl_count} access control lists "
		s << "with a total of #{fw.rule_count} rules. Of the #{fw.rule_count} "
		s << "rules identified, #{an.high_rule_count} had high-severity "
		s << "vulnerabilities, #{an.medium_rule_count} had medium-severity "
		s << "vulnerabilities, and #{an.low_rule_count} had low_severity "
		s << "vulnerabilities.</p>"
		s << "<p>Prometheus identified #{fw.int_count} interfaces on the "
		s << "firewall, #{fw.ints_up} of which were active.</p>"
		s << "</div>\n"

		return s
	end

	##
	# Input: A list of FWConfig::Interface objects
	# 
	# Output: A string containig the list of FWConfig::Interface objects as HTML. 
	# Only includes the name, ip address, subnet mask and status.
	def interfaces_to_html(interfaces)
		vprint_status("Writing interfaces to HTML.")

		h = ''
		unless interfaces.empty?

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
	# Input: A list of FWConfig::Interface objects.
	# 
	# Output: A string containg an HTML table of management protocols in use 
	# on each interface.
	def management_to_html(interfaces)
		vprint_status("Writing remote management to HTML.")
		h = ''

		unless interfaces.empty?

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
	# Input: An Analysis::Summary object.
	#
	# Output: A string containing an HTML representation of the vulnerabilities. 
	# Vulnerabilities are listed in order of severity. 
	def vulnerabilities_to_html(analysis)
		vprint_status("Writing vulnerabilities to HTML.")
		h = "<div id=\"vulnerabilities\">\n"

		unless analysis.highs.empty?
			h << vuln_list_to_html(analysis.highs)
		else
			h << "<h3>High-severity Vulnerabilities</h3>\n"
			h << "<p>No high-severity vulnerabilities to report.</p>\n"
		end

		unless analysis.mediums.empty?
			h << vuln_list_to_html(analysis.mediums)
		else
			h << "<h3>Medium-severity Vulnerabilities</h3>\n"
			h << "<p>No medium-severity vulnerabilities to report.</p>\n"
		end

		unless analysis.lows.empty?
			h << vuln_list_to_html(analysis.lows)
		else
			h << "<h3>Low-severity Vulnerabilities</h3>\n"
			h << "<p>No low-severity vulnerabilities to report.</p>\n"
		end

		h << "</div>\n"
		return h
	end

	##
	# Input: A list of Analysis::Vulnerability objects
	# 
	# Output: A string containg an HTML representation of the list of 
	# vulnerabilities.
	def vuln_list_to_html(vulns)

		h = ''

		vulns.each do |v|
			h << vulnerability_to_html(v)
		end

		return h
	end

	##
	# Input: An Analysis::Vulnerability object
	#
	# Output: A string containing an HTML representation of a vulnerability.
	def vulnerability_to_html(v)
		vprint_status("Writing #{v.name} (#{v.severity.upcase}) to HTML.")
		h = ''

		t = HTMLTable::Table.new( 'Columns' => v.affected[0])

		v.affected[1, v.affected.length].each do |a|
			t.rows << a
		end

		h << "<div>\n"
		h << "<h3>#{v.name} (#{v.severity.upcase})</h3>\n"
		h << "<p><strong>Description:</strong> #{v.desc}</p>\n"
		h << "<p><strong>Solution:</strong> #{v.solution}</p>\n"
		h << t.to_html
		h << "</div>\n"

		return h
	end

	##
	# Input: A list of Config:AccessList objects and a firewall type
	#
	# Output: A string containing an HTML representation of an acl
	#
	# Action: SonicWALL firewalls do not store a protocol with the rule so do 
	# not display the protocol column in the HTML table. Use the type variable 
	# to determine if this is a SonicWALL. 
	def access_lists_to_html(acls, type)
		vprint_status("Writing access control lists to HTML.")
		h = ''

		unless acls.empty?
			h << "<div id=\"access_lists\">\n"
			h << "<h3>Access Control Lists</h3>\n"

			# Do not display the protocol column for SonicWALLs
			if type == 'SonicOS'
				columns = ['ID', 'Enabled', 'Source', 'Destination', 'Action', 'Service']
			else
				columns = ['ID', 'Enabled', 'Protocol', 'Source', 'Destination', 'Action', 'Service']
			end

			acls.each do |a|
				interface = a.interface ? " (#{a.interface})" : ''
				t = HTMLTable::Table.new(
					'Columns' => columns,
					'Header' => a.name + interface
				)
				a.ruleset.each do |r|
					# Do not display the protocol column for SonicWALLs
					if type == 'SonicOS'
						t.rows << [r.num, r.enabled, r.source, r.dest, r.action, r.service]
					else
						t.rows << [r.num, r.enabled, r.protocol, r.source, r.dest, r.action, r.service]
					end
				end

				h << t.to_html
			end

			h << "</div>\n"
		end

		return h
	end

	#-------------------------------------------------------------------------
	# Professional Functionality
	#-------------------------------------------------------------------------

	##
	# Input: A hash of name/IP pairs
	#
	# Output: A string containing an HTML representation of the list of host 
	# names.
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
				print_debug("Host Name: #{name} - #{ip}")
				t.rows << [name, ip]
			end

			h << t.to_html
			h << "</div>\n"
		end

		return h
	end

	##
	# Input: A list of FWConfig::NetworkName objects
	#
	# Output: A string containing an HTML representation of the list of 
	# network names.
	def network_names_to_html(network_names)
		vprint_status("Writing network names to HTML.")
		h = ''

		unless network_names.empty?
			h << "<div id=\"network_names\">\n"
			h << "<h3>Network Names</h3>\n"

			network_names.each do |n|
				if n.hosts.empty? then next end
				t = HTMLTable::Table.new(
					'Columns' => [n.name]
				)
				n.hosts.each do |host|
					print_debug("Network Name: #{host}")
					t.rows << [host]
				end
				h << t.to_html
			end

			h << "</div>\n"

		end

		return h
	end

	##
	# Input: A list of FWConfig::ServiceName objects
	#
	# Output: A string containing an HTML representation of the list of 
	# service names.
	def service_names_to_html(service_names)
		vprint_status("Writing service names to HTML.")
		h = ''

		unless service_names.empty?
			h << "<div id=\"service_names\">\n"
			h << "<h3>Service Names</h3>\n"

			service_names.each do |s|
				if s.ports.empty? then next end
				t = HTMLTable::Table.new(
					'Columns' => [s.name]
				)
				print_debug("Service Name: #{s.name}")
				s.ports.each do |p|
					print_debug("Port: #{p}")
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
