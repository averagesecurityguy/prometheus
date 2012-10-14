#-----------------------------------------------------------------------------
# This module is used to import each of the common modules used throughout 
# the program. Any additional modules that are meant to be used throughout 
# the program should be added und the lib/common directory. The current 
# modules in use are:
#
# PrometheusErrors - defines ParseErrors, Report Errors and Analysis Errors
# PrometheusUI     - used to display color-coded status messages in the 
#                    terminal
# Config           - defines all the objects necessary for holding the 
#                    firewall configuration.
# Vulnerability    - defines a Vulnerabilty object and a Summary object.
#-----------------------------------------------------------------------------
require 'common/errors'
require 'common/ui'
require 'common/config'
require 'common/vulnerability'

def open_config_file(config_file)
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

  
  return config
end
