module Report
module HTMLReport

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
		html.gsub!(/--id--/, firewall.id)
		html.gsub!(/--type--/, firewall.type)
		html.gsub!(/--firmware--/, firewall.firmware)

		# Insert Interfaces
		html.gsub!(/--interfaces--/, html_interfaces(firewall.interfaces))

		# Insert Remote Management
		html.gsub!(/--management--/, html_management(firewall.management))

		# Insert Access Control Lists
		html.gsub!(/--access_lists--/, html_access_lists(firewall.access_lists))
 
	   	return html

	end

	def html_interfaces(int)
		head = ['Name', 'IP Address', 'Subnet Mask']

		return html_table(head, int)
	end

	def html_management(mgmt)
		head = ['Interfaces', 'HTTP', 'HTTPS', 'SSH', 'Telnet']

		return html_table(head, mgmt)
	end

	def html_access_lists(acls)
		h = ''
		acls.each do |a|
			h << '<p class="acl_name">'
			h << a.name
			h << ' (' + a.interface + ')' if a.interface
			h << '</p>'
			h << html_rules(a.ruleset)
		end

		return h
	end

	def html_rules(ruleset)
		head = ['ID', 'Enabled', 'Protocol', 'Source', 'Destination', 'Action', 'Service']
	
		return html_table(head, ruleset)
	end

	def html_table(head, rows)
		table = '<table>'
		table << html_row(head, true)
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
