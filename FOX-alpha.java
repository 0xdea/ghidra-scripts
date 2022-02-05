/*
 * FOX-alpha.java - Fix Objective-C XREFs @Ghidra (AARCH64)
 * Copyright (c) 2021 Marco Ivaldi <raptor@0xdeadbeef.info>
 *
 * "When it encounters a method call, the compiler generates a call to one of
 * the functions objc_msgSend, objc_msgSend_stret, objc_msgSendSuper, or
 * objc_msgSendSuper_stret. Messages sent to an object's superclass (using the
 * super keyword) are sent using objc_msgSendSuper; other messages are sent
 * using objc_msgSend. Methods that have data structures as return values are
 * sent using objc_msgSendSuper_stret and objc_msgSend_stret." 
 * 					-- Apple Objective-C Documentation
 *
 * FOX-alpha is a simple Ghidra script to assist with reverse engineering of
 * iOS apps. It locates all calls to *objc_msgSend* family functions, tries to
 * infer the actual method that gets referenced, and updates cross-references
 * accordingly. If the inferred *objc_msgSend* argument matches more than one
 * method, it tries to determine the class of the called method. When this is
 * not possible, it instead adds a plate comment to all potentially referenced
 * methods that can be then checked manually, to avoid polluting the project
 * with bogus XREFs.
 *
 * This is the first alpha version of FOX. See also the production version
 * maintained by Federico Dotta (@apps3c):
 * https://github.com/federicodotta/ghidra-scripts/tree/main/FOX
 *
 * Usage:
 * - Auto analyze your target binary with the default analyzers (at least)
 * - Copy the script into your ghidra_scripts directory
 * - Open the Script Manager in Ghidra and run the script
 * - You can also run it via the Tools > FOX menu or the shurtcut "X"
 * - Navigate newly updated XREFs (and plate comments if applicable)
 *
 * Caveats:
 * - This script works only with binaries compiled for the AARCH64 architecture
 * - The list of *objc_msgSend* family functions may be incomplete (you can
 *   easily add your own, though)
 * - If the arguments passed to *objc_msgSend* in the x1 and x0 registers are
 *   set in another code block with no fallthrough, the script might infer the
 *   wrong values (could be fixed by looking at decompiled code instead?)
 * - If a method in an external library has the same name of a method in the
 *   binary, and this name is unique in the binary, a wrong XREF to the
 *   internal method might be added when the call is actually made to the
 *   external method (this could be avoided by mapping all external methods via
 *   dynamic analysis techniques).
 * - Large binaries require a long processing time: on my MacBook Air,
 *   processing speed is about 10 calls to *objc_msgSend* per second (could
 *   headless execution improve performance? what about multi-threading?)
 *
 * Inspired by Federico Dotta (@apps3c). Tested with Ghidra v9.2.1.
 */

// This script locates all calls to *objc_msgSend* family functions, tries to
// infer the actual method that gets referenced, and updates cross-references
// accordingly. It works only with AARCH64 binaries. Some other caveats apply
// (see comments to source code).
// @author Marco Ivaldi <raptor@0xdeadbeef.info>
// @category iOS
// @keybinding X
// @menupath Tools.FOX
// @toolbar 

import java.util.List;
import java.util.ArrayList;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.symbol.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.address.*;
import ghidra.app.util.DisplayableEol;

public class FOX-alpha extends GhidraScript 
{
	@Override
	public void run() throws Exception
	{
		// *objc_msgSend* family functions
		// CAVEAT: this list may be incomplete
		List<String> msgSendFuncs = new ArrayList<>(List.of(
			"_objc_msgSend", "_objc_msgSend_stret",
			"_objc_msgSendSuper", "_objc_msgSendSuper_stret",
			"_objc_msgSendSuper2", "_objc_msgSendSuper2_stret"
		));

		// function list
		List<Function> functions = new ArrayList<>();

		printf("\nFOX-alpha - Fix Objective-C XREFs @Ghidra (AARCH64 only)\n");
		printf("Copyright (c) 2021 Marco Ivaldi <raptor@0xdeadbeef.info>\n\n");
		printf("Attempting to fix Objective-C XREFs...\n\n");

		// fix XREFs at each call to *objc_msgSend* family functions
		msgSendFuncs.forEach(m -> getFunctions(m, functions));
		functions.forEach(f -> fixXrefs(f));
	}

	// collect Function objects associated with the specified name
	// @param name function name
	// @param funcs list to add collected Function objects to
	public void getFunctions(String name, List<Function> funcs) 
	{
		SymbolTable st = currentProgram.getSymbolTable();
		SymbolIterator si = st.getSymbolIterator();

		while (si.hasNext()) {
			Symbol s = si.next();
			if ((s.getSymbolType() == SymbolType.FUNCTION) && (!s.isExternal()) && (s.getName().equals(name))) {
				funcs.add(getFunctionAt(s.getAddress()));
			}
		}
	}

	// process XREFs to *objc_msgSend* family functions and attempt to fix them
	// @param dstFunc destination function
	public void fixXrefs(Function dstFunc) 
	{
		// get XREFs
		// the getReferencesTo() method of the FlatProgramAPI is limited to 4096 records
		// for this reason this script uses ReferenceManager::getReferencesTo() instead
		Address dstAddr = dstFunc.getEntryPoint();
		ReferenceManager refman = currentProgram.getReferenceManager();
		ReferenceIterator ri = refman.getReferencesTo(dstAddr);
		Listing listing = currentProgram.getListing(); // speed hack
		int i = 0;

		// process XREFs
		// CAVEAT: large binaries require a long processing time
		while (ri.hasNext()) {
			Reference ref = ri.next();
			i++;

			if (ref.getReferenceType().isCall()) {
				Address callAddr = ref.getFromAddress();
				Function srcFunc = getFunctionContaining(callAddr);

				if ((srcFunc != null) && (!srcFunc.isThunk())) {
					// print *objc_msgSend* call address and caller function name
					String srcName = srcFunc.getName();
					printf("0x%s in %s (%d)\n", callAddr.toString(), srcName, i);

					// infer method name and collect corresponding Function objects
					String methodName = getMethodName(listing, callAddr);
					List<Function> methods = new ArrayList<>();
					getFunctions(methodName, methods);

					// add XREF (or plate comment)
					addXref(listing, methods, callAddr, srcName);
				}
			}
		}
	}

	// add XREF (or plate comment)
	// @param list program listing
	// @param methods list of matching methods
	// @param addr *objc_msgSend* call address
	// @param name *objc_msgSend* caller function name
	public void addXref(Listing list, List<Function> methods, Address addr, String name)
	{
		// if the argument matches only one method, add an XREF
		if (methods.size() <= 1) {
			methods.forEach(m -> addInstructionXref(addr, m.getEntryPoint(), -1, FlowType.UNCONDITIONAL_CALL));
			return;
		}

		// if the argument matches more than one method, try to infer class name and add a corresponding XREF
		String className = getClassName(list, addr);
		if ((className != null) && (className.length() > 0)) {
			methods.forEach(m -> addXrefWithClass(m, addr, className));
		}

		/* if no reference was added, add a plate comment to all matching methods instead */
		if (getReferencesFrom(addr).length < 2) {
			methods.forEach(m -> addComment(m, addr, name));
		}
	}

	// search backwards for the method argument passed to *objc_msgSend* in the x1 register
	// CAVEAT: if the register is set in another code block with no fallthrough, the script might infer the wrong value
	// @param list program listing
	// @param addr *objc_msgSend* call address
	// @return name of the method argument to *objc_msgSend*
	public String getMethodName(Listing list, Address addr)
	{
		InstructionIterator ii = list.getInstructions(addr, false);

		while (ii.hasNext()) {
			Instruction instr = ii.next();
			Register reg = instr.getRegister(0);

			if ((reg != null) && (reg.getName().equals("x1"))) {

				// it looks like the method name is always returned this way,
				// even if there is more than one line in the autocomment...
				DisplayableEol eol = new DisplayableEol(instr, true, true, true, true, 1, true);
				String[] comment = eol.getAutomaticComment();

				// extract the real method name from autocomment, handling empty comments
				if ((comment != null) && (comment.length > 0)) {
						String realName = comment[0].replaceAll("\"", "").replace("= ", "");
						printf("\t%s | %s\n", instr, realName);
						return realName;
				}
				break;
			}
		}
		return null;
	}

	// search backwards for the class argument passed to *objc_msgSend* in the x0 register
	// CAVEAT: if the register is set in another code block with no fallthrough, the script might infer the wrong value
	// @param list program listing
	// @param addr *objc_msgSend* call address
	// @return name of the class argument to *objc_msgSend*
	public String getClassName(Listing list, Address addr)
	{
		CodeUnitFormatOptions opt = new CodeUnitFormatOptions(
			CodeUnitFormatOptions.ShowBlockName.NEVER,
			CodeUnitFormatOptions.ShowNamespace.NEVER, 
			"", false, false, false, true, false, false, false);
		CodeUnitFormat cuf = new CodeUnitFormat(opt);

		InstructionIterator ii = list.getInstructions(addr, false);

		while (ii.hasNext()) {
			Instruction instr = ii.next();
			Register reg = instr.getRegister(0);

			// extract the real class name from operand representation, if present
			if ((reg != null) && (reg.getName().equals("x0"))) {
				String op = cuf.getOperandRepresentationString(instr, 0);
				String realName = op.replace("x0=>", "");
				realName = realName.equals("x0") ? null : realName;
				printf("\t%s | %s\n", instr, realName);
				return realName;
			}
		}
		return null;
	}

	// add an XREF to a method if it belongs to the specified class
	// @param method method to which the XREF is to be added
	// @param addr *objc_msgSend* call address
	// @param name name of class to which the method must belong
	public void addXrefWithClass(Function method, Address addr, String name)
	{
		if (method.getParentNamespace().getName().equals(name)) {
			addInstructionXref(addr, method.getEntryPoint(), -1, FlowType.UNCONDITIONAL_CALL);
		}
	}

	// add a plate comment to a method to indicate a potential XREF
	// @param method method to which the plate comment is to be added
	// @param addr *objc_msgSend* call address
	// @param name name of the caller function
	public void addComment(Function method, Address addr, String name)
	{
		String tag = "Potential XREF: " + addr.toString() + " " + name;

		// set new plate comment
		String cur = method.getComment();
		if (cur == null) {
			method.setComment(tag);
			return;
		}

		// append tag to plate comment if not present already
		String[] comments = method.getCommentAsArray();
		for (int i = 0; i < comments.length; i++) {
			if (comments[i].startsWith(tag)) {
				return;
			}
		}
		method.setComment(cur + "\n" + tag);
	}
}
