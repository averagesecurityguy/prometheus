dir = "./lib/analyze/"
$LOAD_PATH.unshift(dir)
Dir[File.join(dir, "*.rb")].each { |file| require File.basename(file) }

include Analyze
include PrometheusErrors

def analyze_firewall(firewall)
	analysis = {}

	# Run checks on firewall configuration
	analysis["version"] = check_version(firewall)
	analysis["rules"] = check_rules(firewall)
	analysis["remote_admin"] = check_remote_admin(firewall)
	analysis["snmp"] = check_snmp(firewall)

	return analysis
end
