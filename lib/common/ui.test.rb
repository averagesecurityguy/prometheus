require 'ui'
include UI

VERBOSE = true

print_status("Test status message.")
print_good("Test good message.")
print_error("Test error message.")

vprint_status("Verbose status message (should print).")
vprint_good("Verbose good message (should print).")
vprint_error("Verbose error message (should print).")

