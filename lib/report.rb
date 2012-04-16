require 'report/rextable'
require 'report/htmltable'
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
	outfile = set_outfile_name(filename, format)
	templatefile = set_template_name(template, format)

	case format.downcase
		when "text"
			report = generate_text_report(firewall, analysis, templatefile)
		when "html"
			report = generate_html_report(firewall, analysis, templatefile)
		else
			raise ReportError, "Unknown report format #{format}"
	end

	save_report(outfile, report)

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

##
# Takes a file name and report format and creates an appropriate default output 
# file name. The file name could be nil or it could be specified by the -f  
# command line option. If it is nil a default name will be given based on the 
# date, time and format. 

def set_outfile_name(filename, format)

	if filename then 
		return filename
	else
		return "#{Time.now.to_i.to_s}.#{format.downcase}"
	end
end


##
# Takes a template name and a report format and creates the appropriate 
# template file name. The template name could be nil or it could be specified 
# with the -t command line option. It it is nil a default template name will 
# be returned based on the format. Otherwise the specified template name will 
# be returned.

def set_template_name(template, format)

	if template then 
		return template
	else
		return "config/template.#{format.downcase}"
	end
end
