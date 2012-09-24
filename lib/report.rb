#-----------------------------------------------------------------------------
# This module is used to call the appropriate report writer based on the -f 
# command line option. Supported report types are HTML and XML. The code for 
# each report should be in a separate ruby file within lib/report folder and
# should be 'required' below. An appropriate format check and a call to the 
# associated reporting method should be added to the report_firewall method
# below. Each report method is expected to take a FWConfig::Firewall object, a 
# Analysis::Summary object, and an optional template and is expected to return
# a string containing the report. The report is then written to a file using
# the save_report method.
#-----------------------------------------------------------------------------
require 'report/htmltable'
require 'report/html'
require 'report/xml'

include Report::XMLReport
include Report::HTMLReport

##
# Takes a FWConfig::Firewall object a list of Analyze::Vulnerability objects an
# output filename, a report format, and a template file name. Creates a report 
# in the specified format using the specified template file (for HTML format).
# Calls save_report to write the report to disk.

def report_firewall(firewall, analysis, filename, format, template)

	report = nil
	outfile = set_outfile_name(filename, format)
	templatefile = set_template_name(template, format)

	case format.downcase
		when "xml"
			report = generate_xml_report(firewall, analysis)
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
