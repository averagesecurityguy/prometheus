require 'parse/generic_config'
require 'parse/cisco_config'
require 'parse/sonic_config'
#require 'parse/netscreen_config'

def parse_firewall(config, type)
	parsed = nil

	if not ::File.exits?(config)
		raise "File #{config} does not exist."
	end

	case type.downcase
		when "asa"
			parsed = Parse::ASAConfig.new(config)
		when "sonicos"
			parsed = Parse::SonicConfig.new(config)
		when "netscreen"
			parsed = Parse::NetscreenConfig.new(config)
		when "pix"
			parsed = Parse::PixConfig.new(config)
		else
			raise "Unknown firewall type #{type}"
	end

	return parsed
end


