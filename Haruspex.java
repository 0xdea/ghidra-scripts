/*
 * Haruspex.java - Extract Ghidra decompiler's pseudo-code
 * Copyright (c) 2022 Marco Ivaldi <raptor@0xdeadbeef.info>
 *
 * "Et immolantem haruspex Spurinna monuit, caveret periculum, quod non
 * ultra Martias Idus proferretur."
 * 							-- Suetonius
 *
 * Haruspex is a simple Ghidra script to assist with reverse engineering
 * and vulnerability research tasks. It extracts all pseudo-code generated
 * by the Ghidra decompiler in a format that should be suitable to be
 * imported into an IDE, such as VS Code, or parsed by static analysis
 * tools, such as Semgrep.
 *
 * See also:
 * https://github.com/0xdea/ghidra-scripts/blob/main/Rhabdomancer.java
 * https://github.com/0xdea/semgrep-rules
 * https://joern.io/blog/joern-supports-binary/
 * https://www.s3.eurecom.fr/docs/asiaccs22_mantovani.pdf
 *
 * Usage:
 * - Analyze your target binary and manually add/modify functions if needed
 * - Copy the script into your ghidra_scripts directory
 * - Open the Script Manager in Ghidra and run the script
 * - You can also run it via the Tools > Haruspex menu or the shortcut "H"
 * - Enter an output path in which the pseudo-code will be saved
 *
 * Tested with Ghidra v10.2.2.
 */

// This script extracts all pseudo-code generated by the Ghidra decompiler
// in a format that should be suitable to be imported into an IDE, such as
// VS Code, or parsed by static analysis tools, such as Semgrep.
// @author Marco Ivaldi <raptor@0xdeadbeef.info>
// @category VulnDev
// @keybinding H
// @menupath Tools.Haruspex
// @toolbar 

import java.util.List;
import java.util.ArrayList;
import java.io.FileWriter;
import java.io.PrintWriter;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.symbol.*;
import ghidra.program.model.listing.*;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;

public class Haruspex extends GhidraScript 
{
	List<Function> functions;
	DecompileOptions options;
	DecompInterface decomp;
	String outputPath = "/tmp/haruspex.out";
	static int TIMEOUT = 60;

	@Override
	public void run() throws Exception
	{
		printf("\nHaruspex.java - Extract Ghidra decompiler's pseudo-code\n");
		printf("Copyright (c) 2022 Marco Ivaldi <raptor@0xdeadbeef.info>\n\n");
		
		// ask for output directory path
		try {
			outputPath = askString("Output directory path", "Enter the path of the output directory:");
		} catch (Exception e) {
			printf("Output directory not supplied, using default \"%s\".\n", outputPath);
		}

		// get all functions
		functions = new ArrayList<>();
		getAllFunctions();

		// extract pseudo-code of all functions (using default options)
		decomp = new DecompInterface();
		options = new DecompileOptions();
		decomp.setOptions(options);
		decomp.toggleCCode(true);
		decomp.toggleSyntaxTree(true);
		decomp.setSimplificationStyle("decompile");
		if (!decomp.openProgram(currentProgram)) {
			printf("Could not initialize the decompiler, exiting.\n\n");
			return;
		}
		printf("Extracting pseudo-code from %d functions...\n\n", functions.size());
		functions.forEach(f -> extractPseudoCode(f));
	}

	// collect all Function objects into a global ArrayList
	public void getAllFunctions() 
	{
		SymbolTable st = currentProgram.getSymbolTable();
		SymbolIterator si = st.getSymbolIterator();

		while (si.hasNext()) {
			Symbol s = si.next();
			if ( (s.getSymbolType() == SymbolType.FUNCTION) && (!s.isExternal()) ) {
				Function fun = getFunctionAt(s.getAddress());
				if (!fun.isThunk()) {
					functions.add(fun);
				}
			}
		}
	}

	// extract the pseudo-code of a function
	// @param func target function
	public void extractPseudoCode(Function func)
	{
		DecompileResults res = decomp.decompileFunction(func, TIMEOUT, monitor);
		if(res.getDecompiledFunction() != null){
			saveToFile(outputPath, func.getName() + "@" + func.getEntryPoint() + ".c", res.getDecompiledFunction().getC());
		}
		else{
			printf("Can't decompile %s\n\n", func.getName());
		}
	}

	// save results to file
	// @param path name of the output directory
	// @param name name of the output file
	// @param output content to save to file
	public void saveToFile(String path, String name, String output)
	{
		try {
			FileWriter fw = new FileWriter(path + "/" + name);
			PrintWriter pw = new PrintWriter(fw);
			pw.write(output);
			pw.close();

		} catch (Exception e) {
			printf("Cannot write to output file \"%s\".\n\n", path + "/" + name);
			return;
		}
	}
}
