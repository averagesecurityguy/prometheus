module Report
module HTMLReport

  def generate_html_report(fw, an)
    @config = config
	@analysis = analysis

    html = ""
	html << html_head
	html << "<body>\n"
	html << "<div id=\"title\">\n"
	html << "<h1>Prometheus Firewall Analyzer</h1>\n"
	html << "<h2>Report for #{fw.type} firwall #{fw.id}</h2>\n"
	html << "</div>
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
