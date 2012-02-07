require 'firewall/Rule'
require 'firewall/AccessList'
require 'firewall/Interface'

class GenericConfig

  attr_accessor :id, :date, :firmware, :type, :access_lists, :interfaces
  
  def initialize
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