module Report

class HTMLReport

  def initialize(config)
    @config = config
  end

  def to_html
    html = ""
    html += "<h3>#{@config.type}(#{@config.id})</h3>\n"
    html += "<p>The firewall is a [Model] running firmware version [Firmware]. The general configuration of the firewall is as follows:</p>\n"
    html += "<ul>\n"
    html +=  "<li class=\"indent\">[Web Content filtering is enabled.]</li>\n"
    html +=  "<li class=\"indent\">[Gateway Antivirus is enabled.]</li>\n"
    html +=  "<li class=\"indent\">[Intrusion Detection is enabled.]</li>\n"
    @config.interfaces.each do |int|
      html +=  "<li class=\"indent\">The #{int.name} interface is set to #{int.ip} with subnet mask #{int.mask}</li>\n"
    end
    html +=  "</ul>\n"
    html +=  "<p>The firewall is configured with the following access rules:</p>"
	html +=  @config.access_lists_to_html

    return html
  end

end

end
