require 'report/rextable'
require 'report/html'
require 'report/text'

def report_firewall(firewall, analysis, output, format, template)

	include Report::TextReport
	include Report::HTMLReport

	report = nil
	case format.downcase
		when "text"
			report = generate_text_report(firewall, analysis)
		when "html"
			report = generate_html_report(firewall, analysis, template)
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
