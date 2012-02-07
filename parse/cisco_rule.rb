class CiscoRule < Rule
  attr_accessor :protocol
  
  def initialize(action, protocol, source, dest, service)
	@protocol = protocol
	super(action, source, dest, service)
  end
  
  def to_s
    str = "#{@action},#{@protocol},#{@source},#{@dest},#{@service}\n"
	return str
  end
  
  def to_html
    html = "<tr><td>#{@action}</td><td>#{@protocol}<td>#{@source}</td><td>#{@dest}</td><td>#{@service}</td></tr>\n"
	return html
  end  
end
