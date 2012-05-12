module FWConfig

	##
	# Class to hold a firewall configuration.
	# 
	# @name          - firewall name
	# @firmware      - firmware version
	# @type          - firewall type, ASA, PIX, SonicWALL, etc
	# @access_lists  - an array of AccessList objects 
	# @interfaces    - a list of Interface objects 
	# @host_names    - a Hash of name/IP pairs 
	# @service_names - a list of ServiceName objects 
	# @network_names - a list of NetworkName objects
	# rule_count     - number of rules found
	# acl_count      - number of acl entries found
	# int_count      - number of interfaces found
	# ints_up        - number of interfaces that are up
	class FirewallConfig
		attr_accessor :name, :firmware, :type, :access_lists, :interfaces
		attr_accessor :host_names, :service_names, :network_names
  
		def initialize
			@name = nil
			@firmware = nil
			@type = nil
			@access_lists = Array.new
			@interfaces = Array.new
			@host_names = Hash.new
			@service_names = Array.new
			@network_names = Array.new
		end

		##
		# The parser is expected to set @type to 'ASA', 'PIX', or 'SonicOS'. 
		# Anything else raises an error.
		def type=(input)
			if ['ASA', 'PIX', 'SonicOS'].include?(input)
				@type = input
			else
				raise ParseError.new("Invalid input for Config::Firewall.type: #{input}")
			end
		end

		##
		# Count the number of rules identified and return the count
		def rule_count
			rc = 0
			@access_lists.each do |acl|
				rc += acl.ruleset.length
			end
		
			return rc
		end

		##
		# Count the number of ACLs identified and return the count
		def acl_count
			return @access_lists.length
		end

		##
		# Count the number of interfaces and return the count
		def int_count
			return @interfaces.length
		end

		##
		# Count the number of interfaces that are up and return the count
		def ints_up
			up = 0
			@interfaces.each do |i|
				if i.status == 'Up' then up += 1 end
			end

			return up
		end
	end


	##
	# Class to hold access lists. 
	# 
	# @name      - the name of the access list 
	# @interface - the name of the interface the access list applies to  
	# @ruleset   - a list of Rule objects
	class AccessList
		attr_accessor :name, :interface, :ruleset

		def initialize(name)
			@name = name
			@interface = nil
			@ruleset = Array.new
		end
	end


	##
	# Class to hold service names.
	# 
	# @name     - the name of the service 
	# @protocol - the protocol associated with the services 
	# @ports    - a list of strings representing ports or port ranges 
	#             associated with the service.
	class ServiceName
		attr_accessor :name, :protocol, :ports

		def initialize(name)
			@name = name
			@protocol = nil
			@ports = Array.new
		end

	end


	##
	# Class to hold network names. 
	#
	# @name  - the name of the network 
	# @hosts - a list of strings representing the hosts associated with the 
	#          network name.
	class NetworkName
		attr_accessor :name, :hosts

		def initialize(name)
			@name = name
			@hosts = Array.new
		end

	end


	##
	# Class to hold the interfaces. 
	# 
	# @name     - the name of the interface or the IP address if no name is 
	#             defined. 
	# @ip       - the IP address for the interface
	# @mask     - the subnet mask for the interface
	# @status   - is the interface up or down
	# @external - is this an external interface
	# @http     - is HTTP management accessible on this interface
	# @https    - is HTTPS managment accessible on this interface
	# @ssh      - is SSH management accessible on this interface
	# @telnet   - is Telnet management accessible on this interface
	class Interface
		attr_accessor :name, :ip, :mask, :status, :external 
		attr_accessor :http, :https, :ssh, :telnet

		def initialize(name)
			@name = name
			@ip = ' '
			@mask = ' '
			@status = 'Up'
			@external = false
			@http = false
			@https = false
			@ssh = false
			@telnet = false
		end

		##
		# Confirm the input string is in the form of an IP address. If not 
		# raise a parse error.
		def ip=(input)
			if is_ip?(input)
				@ip = input
			else
				raise ParseError.new("Invalid input for Config::Interface.ip: #{input}")
			end
		end

		##
		# Confirm the input string is in the form of a subnet mask. If not
		# raise a parse error.
		def mask=(input)
			if is_mask?(input)
				@mask = input
			else
				raise ParseError.new("Invalid input for Config::Interface.mask: #{input}")
			end
		end

		##
		# The parser is expected to set @status to 'Up' or 'Down'. Anything 
		# else raises an error.
		def status=(input)
			if ((input == 'Up') || (input == 'Down'))
				@status = input
			else
				raise ParseError.new("Invalid input for Config::Interface.status: #{input}")
			end
		end
		
		# Accessor methods for @http

		##
		# Returns @http, which is true or false.
		def http?
			return @http
		end

		##
		# @http is set to true or false but Yes or No is needed for the report. 
		# Return the appropriate response based on the value of @http.
		def http
			return @http ? 'Yes' : 'No'
		end

		##
		# The parser is expected to set @http to true or false. Anything else 
		# raises an error.
		def http=(input)
			if (input.is_a?(TrueClass) || input.is_a?(FalseClass))
				@http = input
			else
				raise ParseError.new("Invalid input for Config::Interface.http: #{input}")
			end
		end

		# Accessor methods for @https

		##
		# Returns @https, which is true or false.
		def https?
			return @https
		end

		##
		# @https is set to true or false but Yes or No is needed for the 
		# report. Return the appropriate response based on the value of 
		# @https.
		def https
			return @https ? 'Yes' : 'No'
		end

		##
		# The parser is expected to set @https to true or false. Anything else 
		# raises an error.
		def https=(input)
			if (input.is_a?(TrueClass) || input.is_a?(FalseClass))
				@https = input
			else
				raise ParseError.new("Invalid input for Config::Interface.https: #{input}")
			end
		end

		# Accessor methods for @ssh

		##
		# Returns @ssh, which is true or false.
		def ssh?
			return @ssh
		end

		##
		# @ssh is set to true or false but Yes or No is needed for the report. 
		# Return the appropriate response based on the value of @ssh.
		def ssh
			return @ssh ? 'Yes' : 'No'
		end

		##
		# The parser is expected to set @ssh to true or false. Anything else 
		# raises an error.
		def ssh=(input)
			if (input.is_a?(TrueClass) || input.is_a?(FalseClass))
				@ssh = input
			else
				raise ParseError.new("Invalid input for Config::Interface.ssh: #{input}")
			end
		end

		# Accessor methods for @telnet

		##
		# Returns @telnet, which is true or false.
		def telnet?
			return @telnet
		end

		##
		# @telnet is set to true or false but Yes or No is needed for the 
		# report. Return the appropriate response based on the value of 
		# @telnet.
		def telnet
			return @telnet ? 'Yes' : 'No'
		end

		##
		# The parser is expected to set @telnet to true or false. Anything 
		# else raises an error.
		def telnet=(input)
			if (input.is_a?(TrueClass) || input.is_a?(FalseClass))
				@telnet = input
			else
				raise ParseError.new("Invalid input for Config::Interface.telnet: #{input}")
			end
		end

		# Accessor methods for @external

		##
		# Returns @external, which is true or false.
		def external?
			return @external
		end

		##
		# The parser is expected to set @external to true or false. Anything 
		# else raises an error.
		def external=(input)
			if (input.is_a?(TrueClass) || input.is_a?(FalseClass))
				@external = input
			else
				raise ParseError.new("Invalid input for Config::Interface.external: #{input}")
			end
		end

	protected

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
			mask = [128, 192, 224, 240, 248, 252, 255]
			
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
				raise ParseError.new("Invalid input for Config::Interface.external: #{input}")
			end
		end
	
	end

	##
	# Class to hold the rules. 
	# 
	# @num     - id number for the rule 
	# @enabled  - is the rule enalbed
	# @protocol - what protocol is in use in the rule
	# @source   - source IP address, host, network, etc
	# @dest     - destination IP address, host, network, etc
	# @action   - Allow or Deny
	# @service  - which services does the rule govern
	# @comment  - any comments or remarks associated with the rule.
	class Rule
		attr_accessor :num, :enabled, :protocol, :source
		attr_accessor :dest, :action, :service, :comment

		def initialize(num)
			@num = num
			@enabled = false
			@protocol = ''
			@source = ''
			@dest = ''
			@action = ''
			@service = ''
			@comment = nil
		end

		# Accessor methods for @enabled

		##
		# Returns @enabled, which is true or false.
		def enabled?
			return @enabled
		end

		##
		# @enabled is set to true or false but Yes or No is needed for the 
		# report. Return the appropriate response based on the value of 
		# @enabled.
		def enabled
			return @enabled ? 'Yes' : 'No'
		end

		##
		# The parser is expected to set @enabled to true or false. Anything 
		# else raises an error.
		def enabled=(input)
			if (input.is_a?(TrueClass) || input.is_a?(FalseClass))
				@enabled = input
			else
				raise ParseError.new("Invalid input for Config::Rule.enabled: #{input}")
			end
		end

		# Accessor methods for @allowed

		##
		# Returns true or false based on whether @action is set to 'Allow'.
		def allowed?
			return @action == 'Allow' ? true : false
		end

		# Accessor methods for @action

		##
		# The parser is expected to set @action to 'Allow' or 'Deny'. Anything 
		# else raises an error.
		def action=(input)
			if ((input == 'Allow') || (input == 'Deny'))
				@action = input
			else
				raise ParseError.new("Invalid input for Config::Rule.action: #{input}")
			end
		end

		# Accessor methods for @source

		##
		# Check input to see if @source should be 'Any'. If so, then set 
		# @source to 'Any', else set @source to the input value. 
		def source=(input)
			if any?(input)
				@source = 'Any'
			else
				@source = input
			end
		end

		# Accessor methods for @dest

		##
		# Check input to see if @dest should be 'Any'. If so, then set @dest 
		# to 'Any', else set @dest to the input value. 
		def dest=(input)
			if any?(input)
				@dest = 'Any'
			else
				@dest = input
			end
		end

		# Accessor methods for @service

		##
		# Check input to see if @service should be 'Any'. If so, the set 
		# @service to 'Any', else set @service to the input value. 
		def service=(input)
			if any?(input)
				@service = 'Any'
			else
				@service = input
			end
		end

	protected

		##
		# Input: a string
		#
		# Output: true or false
		#
		# Action: Check to see if the string is in the list of strings that 
		# indicate an any value. Return true if the string is in the list and 
		# false if it is not. 
		def any?(str)
			return ['any', '0.0.0.0/0'].include?(str.downcase)
		end

	end

end
