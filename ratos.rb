#!/usr/local/bin/ruby -w
#==============================================================================
#	NAME:
#		ratos.rb
#
#	DESCRIPTION:
#		Mach-O/dwarf symbol lookup.
#
#	COPYRIGHT:
#		Copyright (c) 2012-2019, refNum Software
#		All rights reserved.
#
#		Redistribution and use in source and binary forms, with or without
#		modification, are permitted provided that the following conditions
#		are met:
#		
#		1. Redistributions of source code must retain the above copyright
#		notice, this list of conditions and the following disclaimer.
#		
#		2. Redistributions in binary form must reproduce the above copyright
#		notice, this list of conditions and the following disclaimer in the
#		documentation and/or other materials provided with the distribution.
#		
#		3. Neither the name of the copyright holder nor the names of its
#		contributors may be used to endorse or promote products derived from
#		this software without specific prior written permission.
#		
#		THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
#		"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
#		LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
#		A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
#		HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
#		SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
#		LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
#		DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
#		THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
#		(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
#		OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#==============================================================================
# Imports
#------------------------------------------------------------------------------
verbosity = $VERBOSE;
$VERBOSE  = nil;
require "Pathname";
$VERBOSE  = verbosity;

require "GetoptLong";





#==============================================================================
#		Constants
#------------------------------------------------------------------------------
FRAGMENT_HEADER = <<FRAGMENT
#!/usr/local/bin/ruby -w
#==============================================================================
#	NAME:
#		TOKEN_NAME.rb
#
#	DESCRIPTION:
#		Mach-O/dwarf symbol lookup.
#
#	COPYRIGHT:
#		Copyright (c) 2012, refNum Software
#		<http://www.refnum.com/>
#
#		All rights reserved.
#
#		Redistribution and use in source and binary forms, with or without
#		modification, are permitted provided that the following conditions
#		are met:
#
#			o Redistributions of source code must retain the above
#			copyright notice, this list of conditions and the following
#			disclaimer.
#
#			o Redistributions in binary form must reproduce the above
#			copyright notice, this list of conditions and the following
#			disclaimer in the documentation and/or other materials
#			provided with the distribution.
#
#			o Neither the name of refNum Software nor the names of its
#			contributors may be used to endorse or promote products derived
#			from this software without specific prior written permission.
#
#		THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
#		"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
#		LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
#		A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
#		OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
#		SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
#		LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
#		DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
#		THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
#		(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
#		OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#==============================================================================
# Imports
#------------------------------------------------------------------------------
verbosity = $VERBOSE;
$VERBOSE  = nil;
require "Pathname";
$VERBOSE  = verbosity;

require "GetoptLong";





#==============================================================================
#		Constants
#------------------------------------------------------------------------------
FRAGMENT

FRAGMENT_FOOTER = <<'FRAGMENT'





#==============================================================================
#		getOptions : Get the options.
#------------------------------------------------------------------------------
def getOptions(*theInfo)

	# Get the state we need
	theOpts = GetoptLong.new(*theInfo);
	theHash = Hash.new();



	# Collect the options
	theOpts.each do |key, value|
		key          = key.sub("--", "");
		theHash[key] = value;
	end
	
	return(theHash);

end





#==============================================================================
#		printHelp : Print some help.
#------------------------------------------------------------------------------
def printHelp

	puts "";
	puts "Usage:";
	puts "    TOKEN_NAME.rb --arch=xxx --raddr=xxxx --laddr=xxxx";
	puts "";
	puts "Example:";
	puts "    Thread 0 Crashed:";
	puts "    0   AppName                  0x0000451a 0x1000 + 13260";
	puts "                                 ^          ^";
	puts "                   runtime address          load address";
	puts "    1   CoreFoundation           0x37d7342e 0x37d60000 + 78894";
	puts "    2   UIKit                    0x351ec9e4 0x351ce000 + 125412";
	puts "    3   UIKit                    0x351ec9a0 0x351ce000 + 125344";
	puts "";
	puts "    $ ./TOKEN_NAME.rb --arch=armv7 --raddr=0x0000451a --laddr=0x1000";
	puts "    -[CPrefsViewController pickImage:] (CPrefsViewController.mm:374)";
	puts "";
	puts "Notes:";
	puts "    o Supported architectures are: #{MACHO_INFO.keys.join(", ")}\n";
	puts "";
	
	exit(0);

end





#==============================================================================
#		findsym : Perform a symbol lookup.
#------------------------------------------------------------------------------
def findsym()

	# Get the arguments
	theArgs = getOptions(	["--arch",  "-a", GetoptLong::REQUIRED_ARGUMENT],
							["--raddr", "-r", GetoptLong::REQUIRED_ARGUMENT],
							["--laddr", "-l", GetoptLong::REQUIRED_ARGUMENT]);

	theArch        = theArgs["arch"];
	runtimeAddress = theArgs["raddr"];
	loadAddress    = theArgs["laddr"];

	if (!MACHO_INFO.has_key?(theArch) || runtimeAddress == nil || loadAddress == nil)
		printHelp();
	end



	# Get the state we need
	#
	# We accept either hex or decimal addresses, but calculate in decimal.
	runtimeAddress = runtimeAddress.hex if (runtimeAddress =~ /^0x/i);
	loadAddress    = loadAddress.hex    if (loadAddress    =~ /^0x/i);
	segmentAddress = MACHO_INFO[theArch]["vmaddr"];



	# Calculate the target address
	relativeAddress = runtimeAddress - loadAddress;
	targetAddress   = segmentAddress + relativeAddress;



	# Find the address
	DWARF_INFO[theArch].each_value do |theInfo|
	
		lowPC  = theInfo["low"];
		highPC = theInfo["high"];

		if (targetAddress >= lowPC && targetAddress <= highPC)
		
			theName = theInfo["name"];
			theFile = theInfo["file"];
			theLine = theInfo["line"];

			theInfo["lines"].each_slice(2) do |addressLine|
				if (addressLine[0] == targetAddress)
					theLine = addressLine[1];
					break;
				end
			end

			puts "#{theName} (#{theFile}:#{theLine})";
			exit(0);

		end
	
	end

	puts "Unable to find symbol!";

end





#==============================================================================
# Script entry point
#------------------------------------------------------------------------------
findsym();
FRAGMENT





#==============================================================================
#		getFunctionInfo : Get a function's info.
#------------------------------------------------------------------------------
def getFunctionInfo(pathDSym, theArch, theChunk)



	# Get the state we need
	theInfo = Hash.new();



	# Parse the ID	
	if (theChunk =~ /^(0x[0-9a-f]+):\s+TAG_subprogram/);
		theInfo["id"] = $1;
	else
		return(nil);
	end



	# Parse the name
	#
	# Inline functions only have a linkage name, which we must decode.
	if (theChunk =~ /AT_name\( "(.*?)" \)/)
		theInfo["name"] = $1;
	
	elsif (theChunk =~ /AT_MIPS_linkage_name\( "(.*?)" \)/)
		theInfo["name"] = `c++filt "_#{$1}"`.chomp();

	else
		return(nil);
	end



	# Parse the extent
	#
	# The high PC value is the address of the instruction immediately following the
	# subprogram - we subtract 1 to obtain the last instruction within it.
	if (theChunk =~ /AT_low_pc\( (0x[0-9a-f]+) \)/)
		theInfo["low"] = $1.hex;
	else
		return(nil);
	end
	
	if (theChunk =~ /AT_high_pc\( (0x[0-9a-f]+) \)/)
		theInfo["high"] = $1.hex-1;
	else
		return(nil);
	end



	# Parse the file
	#
	# Inline functions may not have a decl_file/line associated with them, however
	# we can find them by looking up their start address.
	if (theChunk =~ /AT_decl_file\( "(.*?)" \)/)
		theInfo["file"] = File.basename($1);
	end

	if (theChunk =~ /AT_decl_line\( (\d+) \)/)
		theInfo["line"] = $1.to_i;
	end

	if (!theInfo.has_key?("file"))
		theAddress = theInfo["low"];
		lineInfo   = `dwarfdump --arch="#{theArch}" --lookup="#{theAddress}" "#{pathDSym}"`;

		if (lineInfo =~ /Line table file: '(.*?)' line (\d+), column \d+ with start address/)
			theInfo["file"] = $1;
			theInfo["line"] = $2;
		end
	end



	# Parse the line numbers
	#
	# By iterating dwarfdump between the start/end addresses, we can collect the line number
	# that corresponds to each addresses.
	#
	# This is a completely brute force way to process this, and some obvious optimisations are:
	#
	#    - Use an architecture-specific stride (however x86 instructions can be 1 byte,
	#      and arm thumb instructions are 2 bytes, so won't save that much).
	#
	#    - Since addresses are sorted on export, only save an address when we see the
	#      line number has changed (assuming we don't ever need to track the column).
	#
	# In practice just saving everything is fine: a 3Mb .dSYM produces about 300Kb of ruby
	# address lookup data, and the overhead of invoking dwarfdump is all up-front.
	theLines = Hash.new();
	theName  = theInfo["name"];
	lowPC    = theInfo["low"];
	highPC   = theInfo["high"];

	puts "        processing #{theName}";

	(lowPC..highPC).each do |theAddress|
		lineInfo = `dwarfdump --arch="#{theArch}" --lookup="#{theAddress}" "#{pathDSym}"`;

		if (lineInfo =~ /Line table file: '.*?' line (\d+), column \d+ with start address/)
			theLines[theAddress] = $1.to_i;
		end
	end

	theInfo["lines"] = theLines;

	return(theInfo);

end





#==============================================================================
#		getSymbolInfo : Get the symbol info.
#------------------------------------------------------------------------------
def getSymbolInfo(pathApp, pathDSym)



	# Get the state we need
	infoMacho = Hash.new();
	infoDwarf = Hash.new();



	# Process the .dsym file
	#
	# The .dsym bundle is dumped to obtain the architectures, the functions for
	# each architecture, and the symbol information (name/file/etc) for each.
	puts "Processing #{File.basename(pathDSym)}...";

	theData      = `dwarfdump "#{pathDSym}"`;
	currentArch  = "";
	currentChunk = "";

	theData.lines.each do |theLine|

		if (theLine =~ /^ File: .* \((.*)\)/)
			currentArch          = $1;
			currentChunk         = "";

			puts "\n    processing #{currentArch}";
			infoDwarf[currentArch] = Hash.new();

		elsif (theLine.include?("TAG_subprogram"))
			currentChunk = theLine;

		elsif (theLine.include?("AT_frame_base"))
			currentChunk += theLine;

			funcInfo = getFunctionInfo(pathDSym, currentArch, currentChunk);
			if (funcInfo != nil)
				funcID = funcInfo["id"];
			
				if (infoDwarf[currentArch].has_key?(funcID))
					raise("Duplicate ID! (#{funcID})");
				else
					infoDwarf[currentArch][funcID] = funcInfo;
					
					# dair
					# break if (infoDwarf[currentArch].size() >= 1)
				end
			end

			currentChunk = "";

		else
			currentChunk += theLine;
		end
	
	end



	# Process the .app
	#
	# The app binary can be queried with otool to obtain the vmaddr for each
	# architecture, which is used to calculate the final address for lookup.
	pathPList = "#{pathApp}/Info";
	bundleExe = `defaults read "#{pathPList}" CFBundleExecutable`.chomp();
	pathMacho = "#{pathApp}/#{bundleExe}";

	infoDwarf.each_key do |theArch|
	
		vmInfo = `otool -l -arch #{theArch} "#{pathMacho}" | grep -A 1 -m 1 "__TEXT"`;
		if (vmInfo =~ /vmaddr (0x[0-9a-f]+)/)
			infoMacho[theArch]           = Hash.new();
			infoMacho[theArch]["vmaddr"] = $1;
		end

	end

	return([infoMacho, infoDwarf]);

end





#==============================================================================
#		exportSymbolicator : Export the symbolicator.
#------------------------------------------------------------------------------
def exportSymbolicator(thePath, infoMacho, infoDwarf)



	# Get the state we need
	appName = File.basename(thePath, ".rb");

	fragmentHeader = FRAGMENT_HEADER.dup();
	fragmentHeader.gsub!("TOKEN_NAME", appName);

	fragmentFooter = FRAGMENT_FOOTER.dup();
	fragmentFooter.gsub!("TOKEN_NAME", appName);



	# Export the script
	File.open(thePath, 'w') do |theFile|

		# Export the header
		theFile.puts(fragmentHeader);



		# Export the Mach-O info
		theFile.puts("MACHO_INFO = {");

		infoMacho.each_pair do |theArch, theInfo|
			vmAddr = theInfo["vmaddr"];
		
			theFile.puts("	\"#{theArch}\" => {");
			theFile.puts("		\"vmaddr\" => #{vmAddr},");
			theFile.puts("	},\n\n");
		end

		theFile.puts("};");
		theFile.puts("\n\n\n");



		# Export the DWARF info
		theFile.puts("DWARF_INFO = {");

		infoDwarf.each_pair do |theArch, theFuncs|
		
			theFile.puts("	\"#{theArch}\" => {");

			theFuncs.keys.sort.each do |funcID|
		
				# Get the state we need
				funcInfo  = infoDwarf[theArch][funcID];
				funcName  = funcInfo["name"];
				funcFile  = funcInfo["file"];
				funcLine  = funcInfo["line"];
				funcLow   = funcInfo["low"];
				funcHigh  = funcInfo["high"];
				funcLines = Array.new();
				
				funcInfo["lines"].keys.sort.each do |pc|
					funcLines << pc;
					funcLines << funcInfo["lines"][pc];
				end
				
				
				# Export the function
				theFile.puts("		\"#{funcID.hex}\" => {");
				theFile.puts("			\"file\"  => '#{funcFile}',");
				theFile.puts("			\"name\"  => '#{funcName}',");
				theFile.puts("			\"line\"  => #{funcLine},");
				theFile.puts("			\"low\"   => #{funcLow},");
				theFile.puts("			\"high\"  => #{funcHigh},");
				theFile.puts("			\"lines\" => [#{funcLines.join(',')}]");
				theFile.puts("		},\n\n");
			end

			theFile.puts("	},\n\n");
		end

		theFile.puts("};");



		# Export the footer
		theFile.puts(fragmentFooter);

	end

end





#==============================================================================
#		getPath : Get a path.
#------------------------------------------------------------------------------
def getPath(thePath)

	if (thePath != nil && File.exists?(thePath))
		thePath = Pathname.new(thePath).realpath();
	end
	
	return(thePath);

end





#==============================================================================
#		getOptions : Get the options.
#------------------------------------------------------------------------------
def getOptions(*theInfo)

	# Get the state we need
	theOpts = GetoptLong.new(*theInfo);
	theHash = Hash.new();



	# Collect the options
	theOpts.each do |key, value|
		key          = key.sub("--", "");
		theHash[key] = value;
	end
	
	return(theHash);

end





#==============================================================================
#		printHelp : Print some help.
#------------------------------------------------------------------------------
def printHelp

	puts "";
	puts "Usage:";
	puts "    ratos.rb --app=xxx --dsym=xxxx --out=xxxx";
	puts "";
	puts "Example:";
	puts "    $ ./ratos.rb --app=/tmp/MyApp.app --dsym=/tmp/MyApp.app.dSYM --out=/tmp/appsym.rb";
	puts "";
	puts "Notes:";
	puts "    o The output is a script, which can be invoked to symbolicate MyApp.app crash logs:";
	puts "        $ ./appsym.rb --arch=armv7 --raddr=0x0000451a --laddr=0x1000";
	puts "        -[CPrefsViewController pickImage:] (CPrefsViewController.mm:374)";
	puts "";

	exit(0);

end





#==============================================================================
#		ratos : Generate a symbol lookup.
#------------------------------------------------------------------------------
def ratos()

	# Get the arguments
	theArgs = getOptions(	["--app",  "-a", GetoptLong::REQUIRED_ARGUMENT],
							["--dsym", "-d", GetoptLong::REQUIRED_ARGUMENT],
							["--out",  "-o", GetoptLong::REQUIRED_ARGUMENT]);

	pathApp  = getPath(theArgs["app"]);
	pathDSym = getPath(theArgs["dsym"]);
	pathOut  = getPath(theArgs["out"]);

	if (pathApp == nil || pathDSym == nil)
		printHelp();
	end



	# Process the file
	infoMacho, infoDwarf = getSymbolInfo(pathApp, pathDSym);

	exportSymbolicator(pathOut, infoMacho, infoDwarf);
	File.chmod(0777,   pathOut);

end





#==============================================================================
# Script entry point
#------------------------------------------------------------------------------
ratos();


