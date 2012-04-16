module Report
module TextReport

	def generate_text_report(firewall, analysis, template)
	
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

		text = File.open(template) {|f| f.read}

		# Replace id, firmware, and type
		text.gsub!(/--name--/, firewall.name)
		text.gsub!(/--type--/, firewall.type)
		text.gsub!(/--firmware--/, firewall.firmware)

		# Insert configuration summary statement
		text.gsub!(/--summary_statement--/, summary_to_text(firewall))

		# Insert Analysis Results
		text.gsub!(/--analysis--/, analysis_to_text(analysis))

		# Insert Interfaces
		text.gsub!(/--interfaces--/, interfaces_to_text(firewall))

		# Insert Remote Management
		text.gsub!(/--management--/, management_to_text(firewall))

		# Insert Access Control Lists
		text.gsub!(/--access_lists--/, access_lists_to_text(firewall))

		# Insert Host Names
		text.gsub!(/--host_names--/, host_names_to_text(firewall))

		# Insert Network Objects
		text.gsub!(/--network_objects--/, network_objects_to_text(firewall))

		# Insert Service Objects
		text.gsub!(/--service_objects--/, service_objects_to_text(firewall))

	    return text
	end


	##
	# Takes a Config::Firewall object and returns a text summary of the firewall 
	# type, name, and firmware version.

	def summary_to_text(fw)

		t =  "The #{fw.type} firewall with hostname #{fw.name} and running "
		t << "firmware version #{fw.firmware} was analyzed with Prometheus "
		t << "on #{Date.today.to_s}.\n"

		return t
	end


	##
	# Takes a Config::Firewall object and returns a table of interfaces formatted 
	# using RexTable.

	def interfaces_to_text(fw)

		tbl = RexTable::Table.new('Columns' => ["Interface", "IP Address", "Subnet Mask", "Status"])
    	fw.interfaces.each do |i|
        	tbl << [i.name, i.ip, i.mask, i.status]
    	end

    	return tbl.to_s

	end
	

	##
	# Takes a Config::Firewall object and returns a table of management interfaces 
	# formatted using RexTable.

	def management_to_text(fw)

		tbl = RexTable::Table.new(	'Columns' => ["Interface", "HTTP", "HTTPS", "SSH", "TELNET"])
		fw.interfaces.each do |i|
			tbl << [i.name, i.http, i.https, i.ssh, i.telnet]
		end

		return tbl.to_s

	end


	##
	# Takes a Config::Firewall object and returns a list of tables of access 
	# control lists formatted using RexTable.

	def access_lists_to_text(fw)

		t = ''
		fw.access_lists.each do |al|
			tbl = RexTable::Table.new(	'Columns' => ["ID", "Enabled", "Action", "Protocol", "Source", "Destination", "Service"], 
										'Header' => al.name.upcase)
    		al.ruleset.each do |r|
    	    	tbl << [r.num, r.enabled, r.action, r.protocol, r.source, r.dest, r.service]
    		end
    
    		t << tbl.to_s + "\n"
		end

		return t

	end


	##
	# Takes a list of Vulnerability objects and returns a list of text 
	# formatted vulnerabilities.

	def analysis_to_text(an)
		
		t = ''
		an.each do |a|
			t << a.name + "\n"
			t << a.desc + "\n\n"
			t << "Recommendation\n"
			t << a.solution + "\n\n"

			case a.type
			when 'rule'
				columns = ['Access List', 'Rule #', 'Source', 'Destination', 'Service']
			when 'management'
				columns = ['Interface']
			end

			tbl = RexTable::Table.new(	'Columns' => columns)
			a.affected.each do |i|
				tbl << i
			end

			t << tbl.to_s + "\n"
		end

		return t

	end

	def host_names_to_text(fw)

		tbl = RexTable::Table.new( 'Columns' => ['Name', 'IP Address'] )
		fw.host_names.each do |k, v|
			tbl << [k, v]
		end

		return tbl.to_s + "\n"
	end

	def network_objects_to_text(fw)

		t = ''
		fw.network_objects.each do |no|
			tbl = RexTable::Table.new('Columns' => [no.name])
    		no.hosts.each do |h|
    	    	tbl << [h]
    		end
    
    		t << tbl.to_s + "\n"
		end

		return t
	end

	def service_objects_to_text(fw)

		t = ''
		fw.service_objects.each do |so|
			tbl = RexTable::Table.new('Columns' => ["#{so.name}(#{so.protocol})"])
    		so.ports.each do |p|
    	    	tbl << [p]
    		end
    
    		t << tbl.to_s + "\n"
		end

		return t
	end


end
end
