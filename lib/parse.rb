require 'parse/sonic'
require 'parse/cisco'

include Parse
include PrometheusErrors

def parse_firewall(config_file, type)

	parsed = nil

	if not File.exists?(config_file)
		raise ParseError, "File #{config} does not exist."
	end

	if not File.file?(config_file)
		raise ParseError, "#{config} is not a file."
	end

	if File.zero?(config_file)
		raise ParseError, "The file #{config} is empty."
	end

	config = File.open(filename) {|f| f.read}
	type.downcase!

	if config =~ /ASA Version/m
		print_status("Parsing ASA configuration file.")
		parsed = parse_asa_config(config)
	elsif config =~ /Sonic/m
		print_status("Parsing SonicWALL configuration.")
		parsed = parse_sonic_config(config)
	else
		raise ParseError, "Unknown firewall type."
	end

	return parsed
end

end
