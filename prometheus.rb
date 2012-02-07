#/usr/bin/ruby

# Copyright 2012 Stephen Haywood
# All rights reserved

require 'optparse'

options = {}
optparse = OptionParser.new do|opts|
	# Firewall configuration file
	options[:config] = ""
	opts.on( '-c', '--config_file FILE', "Firewall configuration to parse." ) do|f|
		options[:config] = f
	end

	# Report output file
	options[:report] = ""
	opts.on( '-r', '--report_file FILE', "Report file to write." ) do |r|
		options[:report] = r
	end

	options[:type] = ""
	opts.on( '-t', '--firewall_type TYPE', "Firewall type." ) do |t|
		options[:type] = t
	end

	# This displays the help screen.
	opts.on( '-h', '--help', 'Display this screen' ) do
		puts opts
		exit
	end
end

optparse.parse!


# Begin main program
require 'parse'
require 'analyze'
require 'report'
require 'ui'

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
		else
			raise "Unknown firewall type #{type}"
	end

	return parsed
end

def analyze_firewall(firewall)
	return nil
end

def report_firewall(firewall, analysis, output, type)
	case type.downcase
		when "text"
			report = Report::TextReport.new(firewall, analysis)
		when "html"
			report = Report::HTMLReport.new(firewall, analysis)
		else
			raise "Unknown report type #{type}"
	end

	save_report(output, report)
end

def save_report(output, report)
	print_status("Saving report to #{output}.")
	file = ::File.open(output, "rb")
	file.write(report)
	file.close
	print_status("Report successfully written.")
end


# Parse the firewall config
begin
	firewall = parse_firewall(options[:config], options[:type])
rescue
	print_error("Error parsing firewall config")
	exit
end

# Analyze the firewall config
analysis = analyze_firewall(firewall)

# Write the firewall report
report_firewall(firewall, analysis)

