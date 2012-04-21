#-----------------------------------------------------------------------------
# This module is used to import each of the common modules used throughout 
# the program. Any additional modules that are meant to be used throughout 
# the program should be added und the lib/common directory. The current 
# modules in use are:
#
# PrometheusErrors - defines ParseErrors, Report Errors and Analysis Errors
# PrometheusUI     - used to display color-coded status messages in the 
#                    terminal
# Config           - defines all the objects necessary for holding the 
#                    firewall configuration.
# Vulnerability    - defines a Vulnerabilty object and a Summary object.
#-----------------------------------------------------------------------------
require 'common/errors'
require 'common/ui'
require 'common/config'
require 'common/vulnerability'

