module Config

	##
	# Class to hold a firewall configuration. access_lists is an array of 
	# Access list objects, interfaces is a list of Interface objects,
	# host_names is a hash of name/IP pairs, service_names is a list of 
	# ServiceName objects, and network_names is a list of NetworkName objects.
	class FirewallConfig
		attr_accessor :name, :firmware, :type, :access_lists, :interfaces
		attr_accessor :service_names, :network_names, :host_names
  
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
			
	end

	# Track access lists. ruleset is a list of Rule objects.
	class AccessList
		attr_accessor :name, :interface, :ruleset

		def initialize(name)
			@name = name
			@interface = nil
			@ruleset = Array.new
		end
	end


	# Track service names. ports is a list of strings representing ports and
	# port ranges.
	class ServiceName
		attr_accessor :name, :protocol, :ports

		def initialize(name)
			@name = name
			@protocol = nil
			@ports = Array.new
		end

	end

	# Track network names. hosts is a list of strings representing hosts.
	class NetworkName
		attr_accessor :name, :hosts

		def initialize(name)
			@name = name
			@hosts = Array.new
		end

	end

	# Track interfaces in use
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

		def ip=(input)
			if is_ip?(input)
				@ip = input
			else
				raise ParseError.new("Invalid input for Config::Interface.ip: #{input}")
			end
		end

		def mask=(input)
			if is_mask?(input)
				@mask = input
			else
				raise ParseError.new("Invalid input for Config::Interface.mask: #{input}")
			end
		end

		def status=(input)
			if is_up?(input)
				@status = 'Up'
			elsif is_down?(input)
				@status = 'Down'
			else
				raise ParseError.new("Invalid input for Config::Interface.status: #{input}")
			end
		end
		
		# Accessor methods for @http
		def http?
			return @http
		end

		def http
			return @http ? 'Yes' : 'No'
		end

		def http=(input)
			if (input.is_a?(TrueClass) || input.is_a?(FalseClass))
				@http = input
			else
				raise ParseError.new("Invalid input for Config::Interface.http: #{input}")
			end
		end

		# Accessor methods for @https
		def https?
			return @https
		end

		def https
			return @https ? 'Yes' : 'No'
		end

		def https=(input)
			if (input.is_a?(TrueClass) || input.is_a?(FalseClass))
				@https = input
			else
				raise ParseError.new("Invalid input for Config::Interface.https: #{input}")
			end
		end

		# Accessor methods for @ssh
		def ssh?
			return @ssh
		end

		def ssh
			return @ssh ? 'Yes' : 'No'
		end

		def ssh=(input)
			if (input.is_a?(TrueClass) || input.is_a?(FalseClass))
				@ssh = input
			else
				raise ParseError.new("Invalid input for Config::Interface.ssh: #{input}")
			end
		end

		# Accessor methods for @telnet
		def telnet?
			return @telnet
		end

		def telnet
			return @telnet ? 'Yes' : 'No'
		end

		def telnet=(input)
			if (input.is_a?(TrueClass) || input.is_a?(FalseClass))
				@telnet = input
			else
				raise ParseError.new("Invalid input for Config::Interface.telnet: #{input}")
			end
		end

		# Is this an external interface?
		def external?
			return @external
		end

		def external=(input)
			if (input.is_a?(TrueClass) || input.is_a?(FalseClass))
				@external = input
			else
				@external = is_external?(input)
			end
		end

	protected
		def is_up?(str)
			return ['up'].include?(str.downcase)
		end

		def is_down?(str)
			return ['down'].include?(str.downcase)
		end

		def is_ip?(str)
			is_ip = true

			o1, o2, o3, o4 = str_to_octet(str)
			if (o1 < 0 || o1 > 255) then is_ip = false end
			if (o2 < 0 || o2 > 255) then is_ip = false end
			if (o3 < 0 || o3 > 255) then is_ip = false end
			if (o4 < 0 || o4 > 255) then is_ip = false end

			return is_ip
		end

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

		def is_external?(str)
			is_external = false

			if str.downcase == 'outside' then is_external = true end
			if str == 'X0' then is_external = true end

			return is_external
		end

		def str_to_octet(str)
			o1, o2, o3, o4 = str.split(".")
			return o1.to_i, o2.to_i, o3.to_i, o4.to_i
		end
	
	end

	# Track rules in rulesets
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
		def enabled?
			return @enabled
		end
	
		def enabled
			return @enabled ? 'Yes' : 'No'
		end

		def enabled=(input)
			if (input.is_a?(TrueClass) || input.is_a?(FalseClass))
				@enabled = input
			else
				raise ParseError.new("Invalid input for Config::Rule.enabled: #{input}")
			end
		end

		# Accessor methods for @allowed
		def allowed?
			return @action == 'Allow' ? true : false
		end

		# Accessor methods for @action
		def action=(input)
			if allow?(input)
				@action = 'Allow'
			elsif deny?(input)
				@action = 'Deny'
			else
				raise ParseError.new("Invalid input for Config::Rule.action: #{input}")
			end
		end

		# Accessor methods for @source
		def source=(input)
			if any?(input)
				@source = 'Any'
			else
				@source = input
			end
		end

		# Accessor methods for @dest
		def dest=(input)
			if any?(input)
				@dest = 'Any'
			else
				@dest = input
			end
		end

		# Accessor methods for @service
		def service=(input)
			if any?(input)
				@service = 'Any'
			else
				@service = input
			end
		end

	protected

		def allow?(str)
			return ['allow', 'permit'].include?(str.downcase)
		end

		def deny?(str)
			return ['deny'].include?(str.downcase)
		end

		def any?(str)
			return ['any', '0.0.0.0/0'].include?(str.downcase)
		end

	end



end
