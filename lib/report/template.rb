module Report
module Template

	def html_template
		template = <<<EOT
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
    <title>Prometheus Firewall Analyzer Report</title>

	<style type="text/css">

		body { 
			color: #555753; 
			background: #dddddd; 
			margin: 0; 
			padding: 0;
			text-align: center;
			font-size: 12px;
			font-family: Georgia, serif;
		}

		h1, h2, h3, h4 {
			font-family: helvetica, sans-serif;
			font-weight: bold;
			margin-top: 8px;
			color: #333333;
			line-height: 1;
		}

		h1 { font-size: 1.5em; }
		h2 { font-size: 1.25em; }
		h3 { font-size: 1em; }

		a:link { 
			font-weight: bold; 
			text-decoration: none; 
			color: #B7A5DF;
		}

		a:visited { 
			font-weight: bold; 
			text-decoration: none; 
			color: #D4CDDC;
		}

		a:hover, a:active { 
			text-decoration: underline; 
			color: #9685BA;
		}
	
		div#banner h1 {
			text-align: center;
			font-size: 2.25em;
			/*padding: 0;*/
		}

		div#banner h2 {
			text-align: center;
			/*padding: 0;*/
		}

		div#container {
			margin-left: auto;
			margin-right: auto;
			margin-top: 16px;
			margin-bottom: 16px;
			width: 900px;
			text-align: left;
			background-color: #ffffff;
			border: 2px solid #333333;
			padding: 8px;
		}

	</style>
</head>
    
<body>
	<div id="container">
		<div id="banner">
    		<h1>Firewall Analysis Report For --id-- </h1>
			<h2>Provided by Prometheus Firewall Analyzer</h2>
		</div>

    	<div id="main">
			<p>Put Introductory text here.</p>

			<h1>Configuration Summary</h1>
			<p>Put configuration intro here.</p>
			<p>ID: --id-- <br />
			FIRMWARE: --firmware-- <br />
			TYPE: --type-- </p>

			<h2>Interfaces</h2>
			--interfaces--

			<h2>Remote Management</h2>
			--management--

			<h2>Access Control Lists</h2>
			--access_lists--

			<h1>Configuration Analysis</h1>
			<p>Put Analysis Intro Here</p>
			--analysis--
		</div>
		
		<div id="footer">
			<p>&copy; 2012 Stephen Haywood</p>
		</div>
	</div>
</body>
</html>
EOT	
		return template
	end
