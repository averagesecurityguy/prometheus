module Prometheus

class DataStore

	attr_accessor :options, :firewall, :analysis

	def initialize
		@options = Hash.new
		@firewall = nil
		@analysis = nil
	end

end

end
