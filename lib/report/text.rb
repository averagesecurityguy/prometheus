module Report
module TextReport

def generate_text_report(fw, an)
	
	rept = ""
	rept << "ID: #{fw.id}\n"
	rept << "FIRMWARE: #{fw.firmware}\n"
	rept << "TYPE: #{fw.type}\n\n"

	rept << "INTERFACES\n"
	tbl = RexTable::Table.new(	'Columns' => ["Interface", "IP Address", "Subnet Mask"])
    fw.interfaces.each do |i|
        tbl << [i.name, i.ip, i.mask]
    end
    rept << tbl.to_s

	rept << "\nREMOTE MANAGEMENT\n"
	tbl = RexTable::Table.new(	'Columns' => ["HTTP", "HTTPS", "SSH", "TELNET"])
	fw.interfaces.each do |i|
		tbl << [i.http ? "Y" : "N", i.https ? "Y" : "N",
				i.ssh ? "Y" : "N", i.telnet ? "Y" : "N"]
	end
	rept << tbl.to_s

	rept << "\nACCESS CONTROL LISTS\n"

	fw.access_lists.each do |al|
		tbl = RexTable::Table.new(	'Columns' => ["ID", "Enabled", "Action", "Protocol", "Source", "Destitnation", "Service"], 
									'Header' => al.name.capitalize)
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
