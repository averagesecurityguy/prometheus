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
