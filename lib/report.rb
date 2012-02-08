require 'report/text_report.rb'
require 'report/html_report.rb'
require 'report/pdf_report.rb'

def report_firewall(firewall, analysis, output, type)
	report = nil
	case type.downcase
		when "text"
			report = Report::TextReport.new(firewall, analysis)
		when "html"
			report = Report::HTMLReport.new(firewall, analysis)
		when "pdf"
			report = Report::PDFReport.new(firewall, analysis)
		else
			raise "Unknown report type #{type}"
	end
end

def save_report(output, report)
	print_status("Saving report to #{output}.")
	file = ::File.open(output, "rb")
	file.write(report)
	file.close
	print_status("Report successfully written.")
end
