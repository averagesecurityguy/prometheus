class CiscoAccessList < AccessList

  attr_accessor :interface
  def initialize(name)
    super(name)
  end
  
  def to_html
    html = "<p class=\"bold\">#{@name} (#{@interface})</p>\n"
	html += "<table cellspacing=\"0\" cellpadding=\"0\" border=\"0\" width=\"700\">\n"
	html += "<tr><th>Action</th><th>Protocol</th><th>Source</th><th>Destination</th><th>Service</th></tr>\n"
	@ruleset.each do |rule|
	  html += rule.to_html
	end
	html += "</table>\n"
	
	return html
  end
  
end