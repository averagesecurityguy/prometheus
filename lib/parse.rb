#-----------------------------------------------------------------------------
# This module is used to call the appropriate firewall parser based on the 
# config type. The code for each parser should be in separate ruby file within 
# lib/parse folder and should be 'required' below. An appropriate config file 
# check and a call to the associated parser should be added to the 
# parse_firewall method below. Each parser is expected to take a configuration 
# file and return a FWConfig::FirewallConfig object.
#-----------------------------------------------------------------------------
require 'parse/sonic'
require 'parse/cisco'

##
# Input: A firewall configuration file
# 
# Output: A FWConfig::FirewallConfig object
#
# Action: Ensures the configuration file is an existing, non-empty file, 
# checks the config to determine the firewall type, and then calls the 
# appropriate parsing function.
def parse_firewall(config_file)

	##
	# Does the file exist?
	if not File.exists?(config_file)
		raise ParseError.new("Configuration file does not exist.")
	end

	##
	# Is it a file?
	if not File.file?(config_file)
		raise ParseError.new("#{config_file} is not a file.")
	end

	##
	# Is it empty?
	if File.zero?(config_file)
		raise ParseError.new("The file #{config_file} is empty.")
	end

	config = File.open(config_file) {|f| f.read}

	##
	# Check the config file for an indication of the firewall type then call 
	# the appropriate parser.
	if config =~ /ASA Version/m
		print_status("Parsing ASA configuration file.")
		return parse_cisco_config(config)
	elsif config =~ /PIX Version/m
		print_status("Parsing PIX configuration file.")
		return parse_cisco_config(config)
	elsif config =~ /Sonic/m
		print_status("Parsing SonicWALL configuration.")
		return parse_sonic_config(config)
	else
		raise ParseError.new("Unknown firewall type.")
	end

end
