module Report

require 'report/html'
require 'report/pdf'
require 'report/word'

def report_firewall(firewall, analysis, output, type)
	include Report
	report = nil
	case type.downcase
		when "text"
			report = TextReport.new(firewall, analysis)
		when "html"
			report = HTMLReport.new(firewall, analysis)
		when "pdf"
			report = PDFReport.new(firewall, analysis)
		else
			raise ReportError, "Unknown report type #{type}"
	end
	save_report(output, report)
end

def save_report(output, report)
	print_status("Saving report to #{output}.")
	file = ::File.open(output, "w")
	file.write(report)
	file.close
	print_status("Report successfully written.")
end

end
