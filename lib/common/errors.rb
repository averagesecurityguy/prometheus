module PrometheusErrors

class PrometheusError < StandardError
	attr_accessor :reason
	def initialize(reason = '')
		self.reason = reason
	end
	def to_s
		"Prometheus Error: #{self.reason}"
	end
end

class ReportError < PrometheusError
	def to_s
		"Report Error: #{self.reason}"
	end
end

class AnalysisError < PrometheusError
	def to_s
		"Analysis Error: #{self.reason}"
	end
end

class ParseError < PrometheusError
	def to_s
		return "Parse Error: #{self.reason}"
	end
end

end
