module Report
module TextReport

def generate_text_report(fw, an)
	
	report = ""
	report << "ID: #{fw.name}\n"
	report << "FIRMWARE: #{fw.firmware}\n"
	report << "TYPE: #{fw.type}\n\n"

	report << "INTERFACES\n"
	tbl = RexTable::Table.new('Columns' => ["Interface", "IP Address", "Subnet Mask", "Status"])
    fw.interfaces.each do |i|
        tbl << [i.name, i.ip, i.mask, i.status]
    end
    report << tbl.to_s

	report << "\nREMOTE MANAGEMENT\n"
	tbl = RexTable::Table.new(	'Columns' => ["Interface", "HTTP", "HTTPS", "SSH", "TELNET"])
	fw.interfaces.each do |i|
		tbl << [i.name, i.http, i.https, i.ssh, i.telnet]
	end
	report << tbl.to_s

	report << "\nACCESS CONTROL LISTS\n"

	fw.access_lists.each do |al|
		tbl = RexTable::Table.new(	'Columns' => ["ID", "Enabled", "Action", "Protocol", "Source", "Destination", "Service"], 
									'Header' => al.name.upcase)
    	al.ruleset.each do |r|
        	tbl << [r.num, r.enabled, r.action, r.protocol, r.source, r.dest, r.service]
    	end
    
    	report << tbl.to_s + "\n"
	end

	report << "\nVULNERABILITIES\n"
	an.each do |a|
		report << a.name + "\n"
		report << a.desc + "\n\n"
		report << "Recommendation\n"
		report << a.solution + "\n\n"

		tbl = RexTable::Table.new(	'Columns' => ["AFFECTED"])
		a.affected.each do |i|
			tbl << [i]
		end

		report << tbl.to_s + "\n"
	end

    return report
end

end
end
