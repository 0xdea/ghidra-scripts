/*
 * Rhabdomancer.java - A Ghidra vulnerability research assistant
 * Copyright (c) 2021-2022 Marco Ivaldi <raptor@0xdeadbeef.info>
 *
 * "For the king of Babylon stands at the parting of the way, at the head of
 * the two ways, to use divination. He shakes the arrows; he consults the
 * teraphim; he looks at the liver." -- Ezekiel 21:21
 *
 * Rhabdomancer is a simple Ghidra script to assist with vulnerability research
 * tasks based on a candidate point strategy, against closed source software
 * written in C/C++. It locates all calls to potentially insecure functions
 * (the candidate points), which have been classified in 3 different tiers of
 * decreasing badness, from 0 to 2. The auditor can then backtrace from these
 * candidate points to find pathways allowing access from untrusted input. 
 *
 * Candidate point strategies are among the fastest ways of identifying the
 * most common classes of vulnerabilities. Of course, without a strong
 * understanding of the code it's hard or impossible to find vulnerabilities
 * other than the proverbial low-hanging fruits. For additional code auditing
 * strategies and a comprehensive guide to software security assessment, I
 * recommend reading "The art of software security assessment", by M. Dowd, J.
 * McDonald, and J. Schuh (Addison Wesley, 2006).
 *
 * Usage:
 * - Auto analyze your target binary with the default analyzers (at least)
 * - Copy the script into your ghidra_scripts directory
 * - Open the Script Manager in Ghidra and run the script
 * - You can also run it via the Tools > Rhabdomancer menu or the shurtcut "Y"
 * - Open Window > Comments and navigate [BAD] candidate points in tier 0-2
 *
 * Inspired by The Ghidra Book (No Starch, 2020). Tested with Ghidra v10.1.1.
 */

// This script locates all calls to potentially insecure functions, in order to
// speed up static analysis for vulnerability research purposes.
// @author Marco Ivaldi <raptor@0xdeadbeef.info>
// @category VulnDev
// @keybinding Y
// @menupath Tools.Rhabdomancer
// @toolbar 

import java.util.List;
import java.util.ArrayList;
import java.util.Map;
import java.util.LinkedHashMap;
import java.util.Iterator;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.symbol.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;

public class Rhabdomancer extends GhidraScript 
{
	@Override
	public void run() throws Exception
	{
		// these functions are generally considered insecure
		// see also https://github.com/x509cert/banned/blob/master/banned.h
		List<String> tier0 = new ArrayList<>(List.of(
			// strcpy family
			"strcpy", "strcpyA", "strcpyW", "wcscpy", "_tcscpy", "_mbscpy", 
			"StrCpy", "StrCpyA", "StrCpyW", 
			"lstrcpy", "lstrcpyA", "lstrcpyW", "_tccpy", "_mbccpy", "_ftcscpy",
			"stpcpy",
			// strcat family
			"strcat", "strcatA", "strcatW", "wcscat", "_tcscat", "_mbscat", 
			"StrCat", "StrCatA", "StrCatW", 
			"lstrcat", "lstrcatA", "lstrcatW", 
			"StrCatBuff", "StrCatBuffA", "StrCatBuffW", "StrCatChainW", 
			"_tccat", "_mbccat", "_ftcscat",
			// sprintf family
			"sprintf", "_sprintf", "_sprintf_c89", 
			"vsprintf", "_vsprintf", "_vsprintf_c89", 
			"swprintf", "vswprintf",
			"_wsprintfA", "_wsprintfW", "sprintfW", "sprintfA", "wsprintf", "wsprintfW", "wsprintfA", 
			"swprintf", "_stprintf", "wvsprintf", "wvsprintfA", "wvsprintfW", "_vstprintf",
			// scanf family
			"scanf", "__isoc99_sscanf", "wscanf", "_tscanf", "sscanf", "_sscanf_c89", 
			"fscanf", "__isoc99_fscanf", "fwscanf", "swscanf", "_stscanf",
			"snscanf", "_snscanf", "snwscanf", "_snwscanf", "_sntscanf",
			// gets family
			"gets", "_getts", "_getws", "_gettws", "getpw",
			// insecure memory allocation on the stack, can also cause stack clash
			"alloca", "_alloca",
			// insecure temporary file creation
			"mktemp", "tmpnam", "tempnam"
		));

		// these functions are interesting and should be checked for insecure use cases
		List<String> tier1 = new ArrayList<>(List.of(
			// strncpy needs explicit null-termination: buf[sizeof(buf) – 1] = '\0'
			"strncpy", "wcsncpy", "_tcsncpy", "_mbsncpy", "_mbsnbcpy", 
			"StrCpyN", "StrCpyNA", "StrCpyNW", "StrNCpy", "strcpynA", "StrNCpyA", "StrNCpyW", 
			"lstrcpyn", "lstrcpynA", "lstrcpynW", "_csncpy", "wcscpyn",
			"stpncpy",
			// strncat must be called with: sizeof(buf) - strlen(buf) - 1 to prevent off-by-one bugs (beware of underflow)
			"strncat", "wcsncat", "_tcsncat", "_mbsncat", "_mbsnbcat", 
			"StrCatN", "StrCatNA", "StrCatNW", "StrNCat", "StrNCatA", "StrNCatW", 
			"lstrncat", "lstrcatnA", "lstrcatnW", "lstrcatn",
			// strlcpy returns strlen(src), which can be larger than the dst buffer
			"strlcpy",
			// strlcat returns strlen(src) + strlen(dst), which can be larger than the dst buffer
			"strlcat",
			// strlen can be dangerous with short integers (and potentially also with signed int)
			"strlen", "lstrlen",
			// string token functions can be dangerous as well
			"strtok", "_tcstok", "wcstok", "_mbstok",
			// snprintf returns strlen(src), which can be larger than the dst buffer
			"snprintf", "_sntprintf", "_snprintf", "_snprintf_c89", "_snwprintf", 
			"vsnprintf", "_vsnprintf", "_vsnprintf_c89",
			"_vsnwprintf", "wnsprintf", "wnsprintfA", "wnsprintfW", "_vsntprintf", 
			"wvnsprintf", "wvnsprintfA", "wvnsprintfW",
			// memory copying functions can be used insecurely, check if size arg can contain negative numbers
			"memcpy", "memccpy", "memmove", "bcopy", 
			"wmemcpy", "wmemmove", "RtlCopyMemory", "CopyMemory",
			// user id and group id functions can be used insecurely, return value must be checked
			"setuid", "seteuid", "setreuid", "setresuid",
			"setgid", "setegid", "setregid", "setresgid", "setgroups", "initgroups",
			// exec* and related functions can be used insecurely
			// functions without "-e" suffix take the environment from the extern variable environ of calling process
			"execl", "execlp", "execle", "execv", "execve", "execvp", "execvpe",
			"system", "fork", "vfork", "clone", "pipe", "popen",
			// i/o functions can be used insecurely
			"open", "open64", "openat", "openat64", "fopen", "fopen64", "freopen", "freopen64", "dlopen",
			"read", "fread", // check read from unreadable paths/files and from writable paths/files
			"write", "fwrite", // check write to unwritable paths/files
			"recv", "recvfrom", // check for null-termination
			"fgets"
		));

		// code paths involving these functions should be carefully checked
		List<String> tier2 = new ArrayList<>(List.of(
			// check for insecure use of environment vars
			"getenv",
			// check for insecure use of arguments
			"getopt", "getopt_long",
			// check for insecure use of memory allocation functions
			// check if size arg can contain negative numbers or zero, return value must be checked
			"malloc", "xmalloc",
			"calloc", // potential implicit overflow due to integer wrapping
			"realloc", "xrealloc", // doesn't initialize memory to zero; realloc(0) is equivalent to free
			"free", // check for incorrect use, double free, use after free
			// check for file access bugs
			"mkdir", "creat",
			"link", "linkat", "symlink", "symlinkat", "readlink", "readlinkat", "unlink", "unlinkat",
			"rename", "renameat",
			"stat", "lstat", "fstat", "fstatat",
			"chown", "lchown", "fchown", "fchownat",
			"chmod", "fchmod", "fchmodat",
			"access", "faccessat",
			// check for temporary file bugs
			"mkstemp", "mkstemp64", "tmpfile", "mkdtemp",
			// check for makepath and splitpath bugs
			"makepath", "_tmakepath", "_makepath", "_wmakepath", 
			"_splitpath", "_tsplitpath", "_wsplitpath",
			// check for format string bugs
			"syslog",
			"printf", "fprintf", "asprintf", "dprintf", 
			"vprintf", "vfprintf", "vasprintf", "vdprintf", 
			"_printf_c89", "_fprintf_c89",
			// check for locale bugs
			"setlocale", "catopen"
			// kill, *sig*, *jmp* functions should be checked for signal-handling related vulnerabilities
			// *sem*, *mutex* functions should be checked for other concurrency-related vulnerabilities
			// new, new []: potential implicit overflow with scalar constructor
			// delete, delete []: check for misalignment with constructor 
			// integer bugs should be also taken into account as they are more subtle and widespread
		));

		// function list
		List<Function> funcs = new ArrayList<>();

		printf("\nRhabdomancer - A Ghidra vulnerability research assistant\n");
		printf("Copyright (c) 2021 Marco Ivaldi <raptor@0xdeadbeef.info>\n\n");
		printf("Listing calls to potentially insecure functions...\n");

		// populate tier map
		Map<String, List<String>> bad = new LinkedHashMap<>();
		bad.put("[BAD 0]", tier0);
		bad.put("[BAD 1]", tier1);
		bad.put("[BAD 2]", tier2);

		// enumerate candidate points at each tier
		Iterator<Map.Entry<String, List<String>>> i = bad.entrySet().iterator();
		while (i.hasNext()) {
			funcs.clear();
			Map.Entry<String, List<String>> entry = i.next();
			printf("\n%s\n\n", entry.getKey());
			entry.getValue().forEach(s -> getFunctions(s, funcs));
			funcs.forEach(f -> listCalls(f, entry.getKey() + " " + f.getName()));
		}
	}

	// collect Function objects associated with the specified name
	// @param name function name
	// @param list list to add collected Function objects to
	public void getFunctions(String name, List<Function> list) 
	{
		SymbolTable st = currentProgram.getSymbolTable();
		SymbolIterator si = st.getSymbolIterator();

		while (si.hasNext()) {
			Symbol s = si.next();
			if ((s.getSymbolType() == SymbolType.FUNCTION) && (!s.isExternal()) && (s.getName().equals(name))) {
				list.add(getFunctionAt(s.getAddress()));
			}
		}
	}

	// process cross-references to a function and list calls
	// @param dstFunc destination function
	// @param tag comment tag
	public void listCalls(Function dstFunc, String tag) 
	{
		String dstName = dstFunc.getName();
		Address dstAddr = dstFunc.getEntryPoint();
		Reference[] refs = getReferencesTo(dstAddr); // limited to 4096 records

		printf("%s is called from:\n", dstName);

		for (int i = 0; i < refs.length; i++) {

			if (refs[i].getReferenceType().isCall()) {
				Address callAddr = refs[i].getFromAddress();
				Function srcFunc = getFunctionContaining(callAddr);

				if ((srcFunc != null) && (!srcFunc.isThunk())) {
					// print call address and caller function
					String srcName = srcFunc.getName();
					long offset = callAddr.getOffset();
					printf("\t0x%x in %s\n", offset, srcName);

					// add pre comment tag at candidate point location
					Listing listing = currentProgram.getListing();
					CodeUnit codeUnit = listing.getCodeUnitAt(callAddr);
					String cur = codeUnit.getComment(CodeUnit.PRE_COMMENT);
					if (cur == null) {
						codeUnit.setComment(CodeUnit.PRE_COMMENT, tag);
					} else {
						if (!cur.startsWith("[BAD ")) {
							codeUnit.setComment(CodeUnit.PRE_COMMENT, tag + "\n" + cur);
						}
					}
				}
			}
		}
	}
}
