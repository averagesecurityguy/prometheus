class SonicAccessList < AccessList

  def initialize(name)
    super(name)
  end
  
  def to_s
    str = "#{@name}\n"
	str += "id,enabled,action,source,destination,service\n"
	@ruleset.each do |rule|
	  str += rule.to_s
	end
	return str
  end
  
  def to_html
    html = "<p class=\"bold\">#{@name}</p>\n"
	html += "<table cellpadding=\"0\" cellspacing=\"0\" border=\"0\" width=\"700\">\n"
	html += "<tr><th>Id</th><th>Enabled</th><th>Action</th><th>Source</th><th>Destination</th><th>Service</th></tr>\n"
	@ruleset.each do |rule|
	  html += rule.to_html
	end
	html += "</table>\n"
	
	return html
  end
  
end