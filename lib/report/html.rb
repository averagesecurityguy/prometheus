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
		html.gsub!(/--summary_statement--/, summary_to_html(firewall))

		# Insert Interfaces
		html.gsub!(/--interfaces--/, interfaces_to_html(firewall.interfaces))

		# Insert Remote Management
		html.gsub!(/--management--/, management_to_html(firewall.interfaces))

		# Insert Access Control Lists
		html.gsub!(/--access_lists--/, access_lists_to_html(firewall.access_lists))

		# Insert Analysis Results
		html.gsub!(/--analysis--/, analysis_to_html(analysis))
	   	return html

	end

	def summary_to_html(fw)

		summary =  "The #{fw.type} firewall with hostname <em>#{fw.name}</em> "
		summary << "and running firmware version <em>#{fw.firmware}</em> was "
		summary << "analyzed with Prometheus Firewall Analyzer (Prometheus) on "
		summary << "#{Date.today.to_s}."

		return summary
	end

	def interfaces_to_html(interfaces)

		head = ['Name', 'IP Address', 'Subnet Mask', 'Status']
		ints = []

		interfaces.each do |i|
			ints << [i.name, i.ip, i.mask, i.status]
		end

		return html_table(head, ints)
	end

	def management_to_html(interfaces)

		head = ['Interface', 'HTTP', 'HTTPS', 'SSH', 'Telnet']
		mgmt = []

		interfaces.each do |i|
			mgmt << [i.name, i.http, i.https, i.ssh, i.telnet]
		end

		return html_table(head, mgmt)
	end

	def analysis_to_html(analysis)
		h = ''
		analysis.each do |a|
			h << vulnerability_to_html(a)
		end

		return h
	end

	def vulnerability_to_html(a)
		h = ''
		case a.type
		when 'rule'
			head = ['Access List', 'Rule #', 'Source', 'Destination', 'Service']
			title = 'Affected Rules'
		when 'management'
			head = nil
			title = 'Affected Interfaces'
		end

		h << "<h3>#{a.name}</h3>"
		h << "<p>#{a.desc} #{a.solution}</p>"
		h << "<h4>#{title}</h4>"
		h << html_table(head, a.affected)

		return h
	end

	def access_lists_to_html(acls)
		h = ''
		acls.each do |a|
			h << "<h4>#{a.name}"
			h << " (#{a.interface})" if a.interface
			h << '</h4>'
			h << rules_to_html(a.ruleset)
		end

		return h
	end

	def rules_to_html(ruleset)

		head = ['ID', 'Enabled', 'Protocol', 'Source', 'Destination', 'Action', 'Service']
		rules = []

		ruleset.each do |r|
			rules << [r.num, r.enabled, r.protocol, r.source, r.dest, r.action, r.service]
		end
	
		return html_table(head, rules)
	end

	def html_table(head, rows)
		if head
			if head.length != rows[0].length
				raise ReportError.new("HTML Report: Mismatched row length while creating table.")
			end
		end

		table = '<table>'

		if head
			table << html_row(head, true)
		end

		rows.each do |row|
			table << html_row(row)
		end

		table << '</table>'
		
		return table
	end

	def html_row(vals, head=false)
		head ? open = '<th>' : open = '<td>'
		head ? close = '</th>' : close = '</td>'

		row = '<tr>'
		vals.each do |v|
			row << open
			if v then row << v.to_s else row << '&#160;' end
			row << close
		end
		row << '</tr>'

		return row
	end

end

end
