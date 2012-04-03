require 'report/rextable'
require 'report/html'
require 'report/text'

include Report::TextReport
include Report::HTMLReport

##
# Takes a Config::Firewall object a list of Analyze::Vulnerability objects an
# output filename, a report format, and a template file name. Creates a report 
# in the specified format using the specified template file (for HTML format).
# Calls save_report to write the report to disk.

def report_firewall(firewall, analysis, filename, format, template)

	report = nil
	case format.downcase
		when "text"
			report = generate_text_report(firewall, analysis)
		when "html"
			report = generate_html_report(firewall, analysis, template)
		else
			raise ReportError, "Unknown report format #{format}"
	end

	save_report(filename, report)

end

##
# Takes a filename and a string representing a report and writes the report to 
# the file specified by filename. It creates the file if it does not exist and
# overwrites the file if it does. 

def save_report(filename, report)
	print_status("Saving report to #{filename}.")
	file = ::File.open(filename, "w")
	file.write(report)
	file.close
	print_status("Report successfully written.")
end
