module PrometheusErrors

	##
	# Generic error class for Prometheus. Use this for Prometheus specific 
	# errors that do not fit in the other classes. 
	class PrometheusError < StandardError
		attr_accessor :reason

		def initialize(reason = '')
			self.reason = reason
		end

		def to_s
			"Prometheus Error: #{self.reason}"
		end
	end

	##
	# Use this for any error specifically related to generating the report.
	class ReportError < PrometheusError
		def to_s
			"Report Error: #{self.reason}"
		end
	end

	##
	# Use this for any error specifically related to analyzing the firewall 
	# configuration.
	class AnalysisError < PrometheusError
		def to_s
			"Analysis Error: #{self.reason}"
		end
	end

	##
	# Use this for any erro specifically related to parsing the firewall 
	# configuration.
	class ParseError < PrometheusError
		def to_s
			return "Parse Error: #{self.reason}"
		end
	end

end
