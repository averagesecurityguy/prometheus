require 'parse/cisco'
require 'parse/sonic'

def parse_firewall(config, type)
	parsed = nil

	if not File.exists?(config)
		raise PrometheusErrors::ParseError, "File #{config} does not exist."
	end

	case type.downcase
		when "asa"
			parsed = Parse::parse_asa_config(config)
		when "sonicos"
			parsed = Parse::parse_sonic_config(config)
		else
			raise PrometheusErrors::ParseError, "Unknown firewall type #{type}"
	end

	return parsed
end


