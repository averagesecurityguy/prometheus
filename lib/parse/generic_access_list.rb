class AccessList

  attr_accessor :name, :ruleset
  
  def initialize(name)
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

