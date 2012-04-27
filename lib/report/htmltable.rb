#-----------------------------------------------------------------------------
# This is a generic method for creating HTML tables. It is modeled after the
# Table module used by REX in the Metasploit program.
#-----------------------------------------------------------------------------
module HTMLTable

class Table

	attr_accessor :header, :columns, :rows

	##
	# Input: A hash containing the options for building the table
	#
	# Output: A new HTMLTable::Table object.
	def initialize(opts={})
		self.header = opts['Header']
		self.columns = opts['Columns'] || []
		self.rows = []
	end

	##
	# Create a new table using the header, columns and rows.
	def to_html()

		html =  "<div>\n"

		# Add the header if one exists
		if self.header
			html << "<h4>#{self.header}</h4>\n"
		end

		# Ensure the number of columns is the same as the number of items in 
		# each row.
		if self.columns.length != self.rows[0].length
			raise ReportError.new("HTML Report: Row length and Column length do not match.")
		end

		# Open the table
		html << "<table>\n"

		# Add column row to the table
		if self.columns
			html << html_row(self.columns, true)
		end

		# Add each of the data rows to the table
		self.rows.each do |row|
			html << html_row(row)
		end

		# Close out the table
		html << "</table>\n</div>\n"
		
		return html
	end

	##
	# Create a table row. If this is a header row then use the <th> tags else 
	# use the <td> tags.
	def html_row(vals, head=false)
		head ? open = '<th>' : open = '<td>'
		head ? close = '</th>' : close = '</td>'

		# Create an individual row.
		row = "<tr>"
		spans = get_row_spans(vals)
		spans.each do |s|
			row << html_cell(open, close, s[0], s[1])
		end
		row << "</tr>\n"

		return row
	end

	##
	# Create a table cell with the appropriate colspan.
	def html_cell(open, close, data, span)
		# Create a cell
		cell = ''

		if span > 1
			cell << open.gsub(/>/, " colspan=\"#{span}\">")
		else
			cell << open
		end

		if data == '' then cell << '&#160;' else cell << data.to_s end
		cell << close

		return cell
	end

	##
	# An individual piece of data can span mulitple columns. Read through the 
	# data values, any data value set to nil represents an increase in the 
	# colspan for the previous data value.
	def get_row_spans(vals)
		spans = []
		vals.each do |v|
			if v then spans << [v, 1] end
			if v == nil then spans.last[1] += 1 end
		end
		return spans
	end

end
end
