module Config

	# Track interfaces in use
	class Interface
		attr_accessor :name, :ip, :mask, :status 
		attr_accessor :http, :https, :ssh, :telnet

		def initialize(name)
			@name = name
			@ip = ' '
			@mask = ' '
			@status = 'Up'
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
			if up?(input)
				@status = 'Up'
			elsif down?(input)
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

		def external?
			external = false

			if @name.downcase == 'outside' then external = true end
			if @name. == 'X0' then external = true end

			return external
		end

	protected
		def up?(str)
			return ['up'].include?(str.downcase)
		end

		def down?(str)
			return ['down'].include?(str.downcase)
		end

# UPDATE THESE
		def is_ip?(str)
			return true
		end

		def is_mask?(str)
			return true
		end
	
	end

	# Track rules in rulesets
	class Rule
		attr_accessor :id, :enabled, :protocol, :source
		attr_accessor :dest, :action, :service

		def initialize(id)
			@id = id
			@enabled = false
			@protocol = ''
			@source = ''
			@dest = ''
			@action = ''
			@service = ''
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

	# Track access lists
	class AccessList
		attr_accessor :name, :interface, :ruleset

		def initialize(name)
			@name = name
			@interface = nil
			@ruleset = Array.new
		end
	end

	class FirewallConfig
		attr_accessor :name, :firmware, :type
		attr_accessor :access_lists, :interfaces
  
		def initialize
			@name = nil
			@firmware = nil
			@type = nil
			@access_lists = Array.new
			@interfaces = Array.new
		end
			
	end

end
