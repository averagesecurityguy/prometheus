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

##
# Input: a string that should contain an ip address
#
# Output: true or false
#
# Action: split the string into octets and check each octet to ensure 
# it is between 0 and 255.
def is_ip?(str)
    is_ip = true

    o1, o2, o3, o4 = str_to_octet(str)
    if (o1 < 0 || o1 > 255) then is_ip = false end
    if (o2 < 0 || o2 > 255) then is_ip = false end
    if (o3 < 0 || o3 > 255) then is_ip = false end
    if (o4 < 0 || o4 > 255) then is_ip = false end

    return is_ip
end

##
# Input: a string that should contain a subnet mask
#
# Output: true or false
#
# Action: split the string into octets and ensure each octet is a 
# valid mask value and that each octet is ordered appropriately.
def is_mask?(str)
    is_mask = false
    mask = [128, 192, 224, 240, 248, 252, 254, 255]
    
    o1, o2, o3, o4 = str_to_octet(str)
    if (mask.include?(o1) && o2 == 0 && o3 == 0 && o4 == 0) then is_mask = true end
    if (o1 == 255 && mask.include?(o2) && o3 == 0 && o4 == 0) then is_mask = true end
    if (o1 == 255 && o2 == 255 && mask.include?(o3) && o4 == 0) then is_mask = true end
    if (o1 == 255 && o2 == 255 && o3 == 255 && mask.include?(o4)) then is_mask = true end

    return is_mask
end

##
# Input: a string that should be in the form of a dotted quad
#
# Output: four integers representing the dotted quads
#
# Action: Split the string into four octets. If any of the octets are 
# nil then this is not a proper dotted quad, raise a parse error. 
def str_to_octet(str)
    o1, o2, o3, o4 = str.split(".")
    if (o1 && o2 && o3 && o4)
        return o1.to_i, o2.to_i, o3.to_i, o4.to_i
    else
        raise ParseError.new("String #{str} is not in dotted quad form.")
    end
end
