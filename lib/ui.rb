module UI

def verbose(v)
	if v then VERBOSE = true else VERBOSE = false end
end

begin
	require 'Win32/Console/ANSI' if RUBY_PLATFORM =~ /win32/
rescue LoadError
	raise 'You must install the win32console gem to use color on Windows.'
end
 
def colorize(text, color_code)
	puts "#{color_code}#{text}\033[0m"
end

def red(text); colorize(text, "\033[31m"); end
def green(text); colorize(text, "\033[32m"); end
def blue(text); colorize(text, "\033[34m"); end

def print_status(msg)
	blue("[*] " + msg)
end

def print_error(msg)
	red("[-] " + msg)
end

def print_good(msg)
	green("[+] " + msg)
end

def vprint_status(msg)
	if VERBOSE then print_status(msg) end;
end

def vprint_error(msg)
	if VERBOSE then print_error(msg) end;
end

def vprint_good(msg)
	if VERBOSE then print_good(msg) end;
end

end
