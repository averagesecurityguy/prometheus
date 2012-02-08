module Parse

require 'parse/sonic_rule'
require 'parse/sonic_access_list'

class SonicConfig < GenericConfig

  attr_accessor :model

  def initialize(wri)
    @wri = wri
    preprocess_wri
    @access_lists = Array.new
	@interfaces = Array.new
    @type = "SonicWall"
    @wri =~ /#STATUS_START(.*)#STATUS_END/m
    parse_id($1)
	@wri =~ /#RULES_START(.*)#RULES_END/m
    parse_access_lists($1)
	@wri =~ /#INTERFACES_START(.*)INTERFACES_END/m
	parse_interfaces($1)
  end


  def preprocess_wri
	@wri.gsub!(/^Nat Policy Table/, "#INTERFACES_END\nNat Policy Table")
	@wri.gsub!(/^Interfaces/, "#INTERFACES_START\nInterfaces")
	@wri.gsub!(/^Rules/, "#RULES_START\nRules")
	@wri.gsub!(/^Bandwidth Management Configurations/, "#RULES_END\nBandwidth Management Configurations")
	@wri.gsub!(/^BWM Rules/, "#RULES_END\nBWM Rules")
    @wri.gsub!(/^Status/, "#STATUS_START\nStatus")
	@wri.gsub!(/^CPU Monitor/, "#STATUS_END\nCPU Monitor")
  end
  
  
  def parse_id(status)
    status =~ /Serial number (.*)/
	@id = $1
	status =~ /(\d+\/\d+\/\d+)\s/
	@date = $1
    status =~ /Firmware version: (.*)/
    @firmware = $1
    status =~ /Model= (.*)/
    @model = $1
  end
  

  def parse_access_lists(rules)
     
    str = ""
    rules.each_line do |line|
	
	  if line =~ /From ([A-Z]+ To [A-Z]+)/ then
        al = SonicAccessList.new($1)
		@access_lists << al
      end
	  if line =~ /Rule [0-9]+ / then str = line end
	  if line =~ /source:/ then str += line end
	  if line =~ /destination:/ then str += line end
	  if line =~ /action:/ then str += line
	    @access_lists.last.ruleset << parse_rule(str)
		str = ""
      end
     	  
   	end
  end
  
  def parse_rule(str)
  
    str =~ /Rule ([0-9]+)/
	id = $1.to_i
	
	str =~ /Rule [0-9]+ \(([a-zA-z]+)\)/
    if $1 == "Enabled" then enabled = "Yes" else enabled = "No" end
	
	str =~ /source:\s+(.*)$/
    source = $1
	
	str =~ /destination:\s(.*)$/ 
	dest = $1
	
	str =~ /action:\s+(.*), service:\s+(.*)/
	action = $1
    service = $2
	
	#str =~ /service:\s([A-Za-z0-9.*- ]+)/
    #service = $1
    
	return SonicRule.new(id, enabled, action, source, dest, service)
	
  end
  
  
  def parse_interfaces(interfaces)
  
    interfaces.each_line do |line|
	
	  if line =~ /Interface Name:\s+([A-Z0-9]+)/ then
        @interfaces << Interface.new($1)
      end
	  if line =~ /IP Address:\s+(.*)/ then @interfaces.last.ip = $1 end
	  if line =~ /Network Mask:\s+(.*)/ then @interfaces.last.mask = $1 end
   	  
   	end
  end


end

end
