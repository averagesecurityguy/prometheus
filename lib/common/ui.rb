module PrometheusUI

	# Do we have color support?
	$color = true

	##
	# The UI uses color-coded status messages, which work fine on *nix boxes 
	# but requires extra modules on Windows. Check to see if we are on 
	# Windows. If so, continue without color support.
	if RUBY_PLATFORM =~ /win32/ or RUBY_PLATFORM =~ /mingw32/

		$color = false
 	end

	##
	# Use ANSI encoding to colorize text.
	def colorize(text, color_code)
		"#{color_code}#{text}\033[0m"
	end

	def red(text); colorize(text, "\033[31m"); end
	def green(text); colorize(text, "\033[32m"); end
	def blue(text); colorize(text, "\033[34m"); end

	##
	# Print status messages.
	def print_status(msg)
		if $color
			puts blue("[*] ") + msg
		else
			puts "[*] " + msg
		end
	end

	##
	# Print error messages.
	def print_error(msg)
		if $color
			puts red("[-] ") + msg
		else
			puts "[-] " + msg
		end
	end

	##
	# Print success messages.
	def print_good(msg)
		if $color
			puts green("[+]") + msg
		else
			puts "[+] " + msg
		end
	end

	##
	# Print line
	def print_line(msg)
		puts msg
	end

	##
	# Print status messages if verbose is true
	def vprint_status(msg)
		if $verbose || $debug then print_status(msg) end;
	end

	##
	# Print error messages if verbose is true
	def vprint_error(msg)
		if $verbose || $debug then print_error(msg) end;
	end

	##
	# Print success messages if verbose is true
	def vprint_good(msg)
		if $verbose || $debug then print_good(msg) end;
	end

	##
	# Print debug messages if debug is true
	def print_debug(msg)
		if $debug
			puts '[debug] ' + msg
		end
	end

end

