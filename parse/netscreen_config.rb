require 'firewall/NetScreenRule'
require 'firewall/NetScreenAccessList'

class NetScreenConfig < GenericConfig

  attr_accessor :model

  def initialize(config)
    @access_lists = Array.new
	@interfaces = Array.new
    @type = "NetScreen"
	@config = config
    
  end


  #Build interface list
      if line =~ /set interface "ethernet\d" zone "(.*)"/ then @interfaces << Interface.new($1) end
      if line =~ /set interface ethernet\d ip (.*)/
        ip, mask = $1.split("/")
        @interfaces.last.ip = ip
        @interfaces.last.mask = mask
      end
  
      #Build Policy list
	  #(^set policy.*?exit$)
	  #Regex scan to input an array
	  @access_lists 
      if line =~ /^set policy id \d+( name ".*")? from "(\w*)" to "(\w*)"  "(.*)" "(.*)" "(.*)"*. (permit|deny)/ then
	  # $1:name $2:source interface $3:dest interface $4:src address $5:dst address $6:service $7:action
        if @access_lists.last == nil
          @access_lists << NetScreenAccessList.new($1)
		  @access_lists.last.ruleset << parse_rule($2)
        elsif @access_lists.last.name != $1
          @access_lists << NetScreenAccessList.new($1)
          @access_lists.last.ruleset << parse_rule($2)
        else
          @access_lists.last.ruleset << parse_rule($2)
        end
      end

      #Access Groups
      if line =~ /access-group (.*)/
        name, dir, int, int_name = $1.split(" ")
        @access_lists.each do |al|
          if al.name == name then al.interface = int_name end
	    end
      end
    end 
  end


  def parse_rule_host(rule_array)
    host = rule_array.shift
    case host
      when "any"
	    return "0.0.0.0/0", rule_array
	  when "host"
	    return rule_array.shift + "/32", rule_array
	  when "object-group"
	    return rule_array.shift, rule_array
	  else
	    return host + "/" + rule_array.shift, rule_array
    end
  end


  def parse_rule_service(rule_array)
    srv = rule_array.shift
    case srv
      when nil
	    return "any"
	  when "eq"
	    return rule_array.shift
	  when "range"
	    return rule_array.shift + " - " + rule_array.shift
    end
  end


  def parse_rule(rule)

    rule_array = rule.split(" ")
    action = rule_array.shift
    protocol = rule_array.shift
    source, rule_array = parse_rule_host(rule_array)
    dest, rule_array = parse_rule_host(rule_array)
    service = parse_rule_service(rule_array)

    return CiscoRule.new(action, protocol, source, dest, service)
  
  end

end