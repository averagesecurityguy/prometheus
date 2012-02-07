class SonicRule < Rule

  attr_accessor :id, :enabled
  
  def initialize(id, enabled, action, source, dest, service)
    @id = id
	@enabled = enabled
	super(action, source, dest, service)
  end
  
  def to_s
    str = "#{@id.to_s},#{@enabled},#{@action},#{@source},#{@dest},#{@service}\n"
	return str
  end
  
  def to_html
    html = "<tr><td>#{@id.to_s}</td><td>#{@enabled}</td><td>#{@action}</td><td>#{@source}</td><td>#{@dest}</td><td>#{@service}</td></tr>\n"
	return html
  end
end