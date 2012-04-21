module PrometheusUI

	color = true

	##
	# The UI uses color-coded status messages, which work fine on *nix boxes 
	# but requires an extra module on Windows. Check to see if we are on 
	# Windows. If so, try to load the module Win32/Console/ANSI. If it is not 
	# available ask the user to install the win32console gem. Continue without 
	# color support.
	begin
		require 'Win32/Console/ANSI' if RUBY_PLATFORM =~ /win32/
	rescue LoadError
		puts "[-] You must install the win32console gem to use color on "
		puts "Windows. Proceeding without color support."
		color = false
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
		if color
			puts blue("[*] ") + msg
		else
			puts "[*] " + msg
		end
	end

	##
	# Print error messages.
	def print_error(msg)
		if color
			puts red("[-] ") + msg
		else
			puts "[-] " + msg
		end
	end

	##
	# Print success messages.
	def print_good(msg)
		if color
			puts green("[+]") + msg
		else
			puts "[+] " + msg
		end
	end

	##
	# Print status messages if verbose is true
	def vprint_status(msg)
		if $verbose then print_status(msg) end;
	end

	##
	# Print error messages if verbose is true
	def vprint_error(msg)
		if $verbose then print_error(msg) end;
	end

	##
	# Print success messages if verbose is true
	def vprint_good(msg)
		if $verbose then print_good(msg) end;
	end

end

