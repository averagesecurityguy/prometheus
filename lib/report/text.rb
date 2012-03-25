module Report
module TextReport

def generate_text_report(fw, an)
	
	rept = ""
	rept << "ID: #{fw.name}\n"
	rept << "FIRMWARE: #{fw.firmware}\n"
	rept << "TYPE: #{fw.type}\n\n"

	rept << "INTERFACES\n"
	tbl = RexTable::Table.new('Columns' => ["Interface", "IP Address", "Subnet Mask", "Status"])
    fw.interfaces.each do |i|
        tbl << [i.name, i.ip, i.mask, i.status]
    end
    rept << tbl.to_s

	rept << "\nREMOTE MANAGEMENT\n"
	tbl = RexTable::Table.new(	'Columns' => ["Interface", "HTTP", "HTTPS", "SSH", "TELNET"])
	fw.interfaces.each do |i|
		tbl << [i.name, i.http, i.https, i.ssh, i.telnet]
	end
	rept << tbl.to_s

	rept << "\nACCESS CONTROL LISTS\n"

	fw.access_lists.each do |al|
		tbl = RexTable::Table.new(	'Columns' => ["ID", "Enabled", "Action", "Protocol", "Source", "Destitnation", "Service"], 
									'Header' => al.name.upcase)
    	al.ruleset.each do |r|
        	tbl << [r.id, r.enabled, r.action, r.protocol, r.source, r.dest, r.service]
    	end
    
    	rept << tbl.to_s
		rept << "\n"
	end

    return rept
end

end
end
