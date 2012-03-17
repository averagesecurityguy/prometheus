require 'parse/parse'

def parse_firewall(config_file)

	if not File.exists?(config_file)
		raise ParseError, "File #{config_file} does not exist."
	end

	if not File.file?(config_file)
		raise ParseError, "#{config_file} is not a file."
	end

	if File.zero?(config_file)
		raise ParseError, "The file #{config_file} is empty."
	end

	config = File.open(config_file) {|f| f.read}

	if config =~ /ASA Version/m
		print_status("Parsing ASA configuration file.")
		parse_asa_config(config)
	elsif config =~ /Sonic/m
		print_status("Parsing SonicWALL configuration.")
		return parse_sonic_config(config)
	else
		raise ParseError, "Unknown firewall type."
	end

end
