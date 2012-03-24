module Config

require 'ipaddr'

	# Track whether SNMP is enabled, to which servers traps are sent, and the
	# community name used.
	Snmp = Struct.new( :enabled, :trap_servers, :community )

	# Track interfaces in use
	class Interface
		attr_accessor :name, :ip, :mask, :status 
		attr_accessor :http, :https, :ssh, :telnet

		def initialize(name)
			@name = name
			@ip = ''
			@mask = ''
			@status = 'UP'
			@http = 'No'
			@https = 'No'
			@ssh = 'No'
			@telnet = 'No'
			@yes_no = ["Yes", "No"]
			@up_down = ["UP", "DOWN", "Up", "Down"]
		end

		def status=(str)
			if @up_down.include?(str)
				@status = str
			else
				raise ParseError("Invalid input for Config::Interface.status: #{str}")
			end
		end

		def http=(str)
			if @yes_no.include?(str)
				@http = str
			else
				raise ParseError("Invalid input for Config::Interface.http: #{str}")
			end
		end

		def https=(str)
			if @yes_no.include?(str)
				@https = str
			else
				raise ParseError("Invalid input for Config::Interface.https: #{str}")
			end
		end

		def ssh=(str)
			if @yes_no.include?(str)
				@ssh = str
			else
				raise ParseError("Invalid input for Config::Interface.ssh: #{str}")
			end
		end

		def telnet=(str)
			if @yes_no.include?(str)
				@telnet = str
			else
				raise ParseError("Invalid input for Config::Interface.telnet: #{str}")
			end
		end
	end

	# Track rules in rulesets
	class Rule
		attr_accessor :id, :enabled, :protocol, :source
		attr_accessor :dest, :action, :service

		def initialize(id)
			@id = id
			@enabled = 'No'
			@protocol = ''
			@source = ''
			@dest = ''
			@action = ''
			@service = ''
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
