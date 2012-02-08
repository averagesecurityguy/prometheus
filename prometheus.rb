#!/usr/bin/ruby

# Copyright 2012 Stephen Haywood
# All rights reserved

require 'optparse'

options = {}
optparse = OptionParser.new do|opts|
	# Firewall configuration file
	options[:config] = ""
	opts.on( '-c', '--config_file FILE', "Firewall configuration to parse." ) do|c|
		options[:config] = c
	end

	# Firewall type
	options[:type] = ""
	opts.on( '-t', '--firewall_type TYPE', "Firewall type." ) do |t|
		options[:type] = t
	end

	# Report output file
	options[:report] = ""
	opts.on( '-r', '--report_file FILE', "Report file to write." ) do |r|
		options[:report] = r
	end
	
	# Report format
	options[:format] = ""
	opts.on( '-f', '--report_format FORMAT', "Report format to use.") do |f|
		options[:format] = f
	end

	# This displays the help screen.
	opts.on( '-h', '--help', 'Display this screen' ) do
		puts opts
		exit
	end
end

optparse.parse!


# Begin main program
$LOAD_PATH << './lib'

require 'parse'
require 'analyze'
require 'report'
require 'errors'
require 'ui'

include UI

firewall = nil
analysis = nil
report = nil

# Parse the firewall config
begin
	firewall = parse_firewall(options[:config], options[:type])
rescue
	print_error("Error parsing firewall configuration.")
	exit
end

# Analyze the firewall config
if firewall
	analysis = analyze_firewall(firewall)
	begin
		report = report_firewall(firewall, analysis, options[:format])
	rescue
		print_error("Error creating report.")
	end
	
	if report
		save_report(report)
	end
		
else
	print_error("Firewall configuration is empty.")
	exit
end
