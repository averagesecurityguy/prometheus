require 'firewall/PixAccessList'
require 'firewall/PixRule'

class PixConfig < GenericConfig

  def initialize(config)
    @access_lists = Array.new
    @interfaces = Array.new
    @type = "Pix"
    config.each_line do |line|
      if line =~ /^hostname (.*)$/ then @id = $1  end
      if line =~ /^Pix Version (.*)$/ then @firmware = $1 end
      if line =~ /^: Written by (.*) at (.*)/ then
        time, zone, weekday, month, day, year = $2.split(" ")
		@date = "#{month}/#{day}/#{year}"
      end

      #Build interface list
      if line =~ /^interface (.*)/ then @interfaces << Interface.new($1) end
      if line =~ /^ ip address (.*)/
        ip, mask = $1.split(" ")
        @interfaces.last.ip = ip
        @interfaces.last.mask = mask
      end
  
      #Build Access list
      if line =~ /access-list\s(\w*)\s(.*)/ then
        if @access_lists.last == nil
		  puts "First IF"
          @access_lists << PixAccessList.new($1)
		  @access_lists.last.ruleset << parse_rule($2)
        elsif @access_lists.last.name != $1
		  puts "Elsif"
          @access_lists << PixAccessList.new($1)
          @access_lists.last.ruleset << parse_rule($2)
        else
		  puts "Last else"
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
	  when "object-group"
		return rule_array.shift
    end
  end


  def parse_rule(rule)

	#if rule != ""
		puts "Before Processing: #{rule}"
		rule_array = rule.split(" ")
		action = rule_array.shift
		protocol = rule_array.shift
		source, rule_array = parse_rule_host(rule_array)
		dest, rule_array = parse_rule_host(rule_array)
		service = parse_rule_service(rule_array)
		puts "After Processing: #{action} - #{protocol} - #{source} - #{dest} - #{service}"

		return PixRule.new(action, protocol, source, dest, service)
	#end
  
  end

end

