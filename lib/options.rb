module Options

# Global options
options = {}

# Load options from configuration file
def load_options
	options[:html_template] = File.join(options[:base], 'config/template.html')
	options[:logo] = File.join(options[:base], 'config/logo.png')
end

end
