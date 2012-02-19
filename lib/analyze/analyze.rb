module Analyze

	dir = "analyze/"
	$LOAD_PATH.unshift(dir)
	Dir[File.join(dir, "*.rb")].each { |file| puts file; require File.basename(file) }

end
