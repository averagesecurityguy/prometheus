Installing Prometheus
=====================
Prometheus is a Ruby application and will run on any system running a recent 
version (1.8.7 or higher) of Ruby. To install Prometheus use the following
steps:

1.  Create a directory called prometheus.
2.  Extract the prometheus files into the directory.
3.  CD into the prometheus directory and run ./prometheus.rb -h

How to Use Prometheus
=====================
To use Prometheus, specify a configuration file to parse using the -c option. 
Prometheus defaults to creating an HTML report in the current directory using 
the default HTML template. To specify a custom template, use the -t option. 
If you are using Prometheus Pro, then use the -f option to specify an 
alternative report format. Currently, XML is the only alternative.

	Usage: ./prometheus.rb -c config_file [options]
    	-c, --config_file FILE           Firewall configuration to parse.
    	-r, --report_file FILE           Report file to write.
    	-f, --format FORMAT              Report format to use.
    	-t, --template FILE              File to use as template.
    	-v, --verbose                    Print verbose output.
    	-d, --debug                      Print debug output (very verbose).
    	-h, --help                       Display this screen

How To Use A Custom HTML Template
=================================
To use a custom template, first, create an HTML file and place tags in the 
file to tell Prometheus where to insert the configuration and vulnerability 
elements. Currently, Prometheus supports the following tags:

    --name--                Firewall name.
    --type--                Firewall type.
    --firmware--            Firmware version.
    --summary_statement--   Summary statement.
    --analysis--            Identified vulnerabilities.
    --interfaces--          Firewall interfaces.
    --management--          Management interfaces.
    --access_lists--        Access control lists.
	--host_names--			List of host names (Professional only).
	--network_names--		List of network names (Professional only).
	--service_names--		List of service names (Professional only).

Next, specify the custom template to use with the -t option. To see an example 
of how to build a custom template, look at the default HTML template, 
template.html, in the config directory. It is recommended that you not modify 
template.html unless you make a backup copy first.
