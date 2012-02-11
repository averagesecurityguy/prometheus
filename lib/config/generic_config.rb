module Config

class Snmp
	# Track whether SNMP is enabled, to which servers traps are sent, and the
	# community name used.

	attr_accessor :enabled, :trap_servers, :community

	def initialize
		@enabled = nil
		@trap_servers = Array.new
		@community = nil
	end
end

class ManagementInterfaces
	# Track the interfaces that are allowed to manage the firewall and the 
	# protocols allowed.

	attr_accessor :http, :https, :ssh, :telnet

	def initialize
		@http = Array.new
		@https = Array.new
		@ssh = Array.new
		@telnet = Array.new
	end
end

class Interface

  attr_accessor :name, :ip, :mask
  
  def initialize(name)
    @name = name
  end
  
end

class Rule

  attr_accessor :id, :source, :dest, :action, :service
  
  def initialize(id, action, source, dest, service)
	@id = id
	@action = action
	@source = source
	@dest = dest
	@service = service
  end
      
  def to_s
    str = "#{@action},#{@source},#{@dest},#{@service}\n"
	return str
  end
  
  def to_html
    html = "<tr><td>#{@action}</td><td>#{@source}</td><td>#{@dest}</td><td>#{@service}</td></tr>\n"
	return html
  end

end

class AccessList

  attr_accessor :enabled, :name, :ruleset
  
  def initialize(name)
	@enabled = nil
    @ruleset = Array.new
	@name = name
  end
  
  def to_s
    str = "#{@name}\n"
	str += "Action,Source,Destination,Service\n"
	@ruleset.each do |rule|
	  str += rule.to_s
	end
	return str
  end
  
  def to_html
    html = "<h3>#{@name}</h3>\n"
	html += "<table cellspacing=\"0\" border=\"0\">\n"
	html += "<col width=\"30\" /><col width=\"80\" /><col width=\"60\" /><col width=\"300\" /><col width=\"300\" /><col width=\"300\" />"
	html += "<tr><th>Action</th><th>Source</th><th>Destination</th><th>Service</th></tr>\n"
	@ruleset.each do |rule|
	  html += rule.to_html
	end
	html += "</table>\n"
	
	return html
  end

end

class FirewallConfig

	attr_accessor :id, :date, :firmware, :type, :snmp, :access_lists, :interfaces
  
	def initialize
		@id = nil
		@date = nil
		@firmware = nil
		@type = nil
		@snmp = Snmp.new
		@management = ManagementInterfaces.new
		@access_lists = Array.new
		@interfaces = Array.new
		@nat_entries = Array.new
		@names = Hash.new
		@groups = Hash.new
	end
  
	def id_to_html
		html = "<p>Configuration ID: #{@id}</p>\n"
		html += "<p>Date: #{@date}</p>\n"
		html += "<p>Firmware: #{@firmware}</p>"
		return html
 	end
   
	def interfaces_to_html
		html = ""
		@interfaces.each do |int|
			html += int.to_html
		end
		return html
	end
  
	def access_lists_to_html
		html = ""
		@access_lists.each do |al|
			html += al.to_html
		end
		return html
	end
end

end
