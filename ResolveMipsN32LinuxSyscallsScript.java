/*
 * ResolveMipsN32LinuxSyscallsScript.java - MIPS N32 Linux
 * Copyright (c) 2022 Marco Ivaldi <raptor@0xdeadbeef.info>
 *
 * "The only intuitive interface is the nipple." -- Anonymous
 *
 * ResolveMipsN32LinuxSyscallsScript is a script based on the original
 * ResolveX86orX64LinuxSyscallsScript distributed with Ghidra. It uses
 * overriding references and the symbolic propogator (sic) to resolve
 * system calls in MIPS N32 binaries, as described in the Advanced Ghidra
 * Class documentation available at:
 * https://github.com/NationalSecurityAgency/ghidra/blob/master/GhidraDocs/
 *
 * This script can assist in analyzing static binaries. It was tested with
 * Ghidra v10.1.1 on an ELF 32-bit MSB executable, MIPS, N32 MIPS64 rel2
 * version 1 (SYSV), statically linked, stripped Linux binary (Cavium
 * Octeon III processor). Porting to other architectures should be trivial.
 *
 * NOTE.
 * The file syscall_numbers/mips_n32_linux_syscall_numbers must be copied
 * into /Ghidra/Features/Base/data/ in your Ghidra installation directory.
 */

//Uses overriding references and the symbolic propogator (sic) to resolve
//system calls
//@author NSA and Marco Ivaldi <raptor@0xdeadbeef.info>
//@category Analysis

import java.io.*;
import java.util.*;
import java.util.Map.Entry;
import java.util.function.Predicate;

import generic.jar.ResourceFile;
import ghidra.app.cmd.function.ApplyFunctionDataTypesCmd;
import ghidra.app.cmd.memory.AddUninitializedMemoryBlockCmd;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.plugin.core.analysis.ConstantPropagationContextEvaluator;
import ghidra.app.script.GhidraScript;
import ghidra.app.services.DataTypeManagerService;
import ghidra.app.util.opinion.ElfLoader;
import ghidra.framework.Application;
import ghidra.program.model.address.*;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.lang.BasicCompilerSpec;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.symbol.*;
import ghidra.program.util.ContextEvaluator;
import ghidra.program.util.SymbolicPropogator;
import ghidra.program.util.SymbolicPropogator.Value;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * This script will resolve system calls for MIPS N32 Linux binaries.
 * It should be straightforward to modify this script for other cases.
 */
public class ResolveMipsN32LinuxSyscallsScript extends GhidraScript {

	private static final String MIPS = "MIPS";

	private static final String SYSCALL_SPACE_NAME = "syscall";

	private static final int SYSCALL_SPACE_LENGTH = 0x10000;

	//this is the name of the userop (aka CALLOTHER) in the pcode translation of the
	//native "syscall" instruction
	private static final String SYSCALL_MIPS_CALLOTHER = "syscall";

	//a set of names of all syscalls that do not return
	private static final Set<String> noreturnSyscalls = Set.of("exit", "exit_group");

	//tests whether an instruction is making a system call
	private Predicate<Instruction> tester = ResolveMipsN32LinuxSyscallsScript::checkMipsN32Instruction;

	//register holding the syscall number
	private String syscallRegister = "v0";

	//TODO
	//datatype archive containing signature of system calls
	//private String datatypeArchiveName = "generic_clib_mips_n32";

	//file containing map from syscall numbers to syscall names
	//note that different architectures can have different system call numbers, even
	//if they're both Linux...
	private String syscallFileName = "mips_n32_linux_syscall_numbers"; 

	//the type of overriding reference to apply 
	private RefType overrideType = RefType.CALLOTHER_OVERRIDE_CALL;

	//the calling convention to use for system calls (must be defined in the appropriate .cspec file)
	//see /Ghidra/Processors/MIPS/data/languages/mips64_32_n32.cspec
	private String callingConvention = "__stdcall";

	@Override
	protected void run() throws Exception {

		if (!(currentProgram.getExecutableFormat().equals(ElfLoader.ELF_NAME) &&
			currentProgram.getLanguage().getProcessor().toString().equals(MIPS))) {
			popup("This script is intended for MIPS Linux files");
			return;
		}

		//get the space where the system calls live.  
		//If it doesn't exist, create it.
		AddressSpace syscallSpace =
			currentProgram.getAddressFactory().getAddressSpace(SYSCALL_SPACE_NAME);
		if (syscallSpace == null) {
			//don't muck with address spaces if you don't have exclusive access to the program.
			if (!currentProgram.hasExclusiveAccess()) {
				popup("Must have exclusive access to " + currentProgram.getName() +
					" to run this script");
				return;
			}
			Address startAddr = currentProgram.getAddressFactory().getAddressSpace(
				BasicCompilerSpec.OTHER_SPACE_NAME).getAddress(0x0L);
			AddUninitializedMemoryBlockCmd cmd = new AddUninitializedMemoryBlockCmd(
				SYSCALL_SPACE_NAME, null, this.getClass().getName(), startAddr,
				SYSCALL_SPACE_LENGTH, true, true, true, false, true);
			if (!cmd.applyTo(currentProgram)) {
				popup("Failed to create " + SYSCALL_SPACE_NAME);
				return;
			}
			syscallSpace = currentProgram.getAddressFactory().getAddressSpace(SYSCALL_SPACE_NAME);
		}
		else {
			printf("AddressSpace %s found, continuing...\n", SYSCALL_SPACE_NAME);
		}

		//get all of the functions that contain system calls
		//note that this will not find system call instructions that are not in defined functions
		Map<Function, Set<Address>> funcsToCalls = getSyscallsInFunctions(currentProgram, monitor);

		if (funcsToCalls.isEmpty()) {
			popup("No system calls found (within defined functions)");
			return;
		}

		//get the system call number at each callsite of a system call.
		//note that this is not guaranteed to succeed at a given system call call site -
		//it might be hard (or impossible) to determine a specific constant
		Map<Address, Long> addressesToSyscalls =
			resolveConstants(funcsToCalls, currentProgram, monitor);

		if (addressesToSyscalls.isEmpty()) {
			popup("Couldn't resolve any syscall constants");
			return;
		}

		//get the map from system call numbers to system call names
		//you might have to create this yourself!
		Map<Long, String> syscallNumbersToNames = getSyscallNumberMap();

		//at each system call call site where a constant could be determined, create
		//the system call (if not already created), then add the appropriate overriding reference
		//use syscallNumbersToNames to name the created functions
		//if there's not a name corresponding to the constant use a default 
		for (Entry<Address, Long> entry : addressesToSyscalls.entrySet()) {
			Address callSite = entry.getKey();
			Long offset = entry.getValue();
			Address callTarget = syscallSpace.getAddress(offset);
			Function callee = currentProgram.getFunctionManager().getFunctionAt(callTarget);
			if (callee == null) {
				String funcName = "syscall_" + String.format("%08X", offset);
				if (syscallNumbersToNames.get(offset) != null) {
					funcName = syscallNumbersToNames.get(offset);
				}
				callee = createFunction(callTarget, funcName);
				callee.setCallingConvention(callingConvention);

				//check if the function name is one of the non-returning syscalls
				if (noreturnSyscalls.contains(funcName)) {
					callee.setNoReturn(true);
				}
			}
			Reference ref = currentProgram.getReferenceManager().addMemoryReference(callSite,
				callTarget, overrideType, SourceType.USER_DEFINED, Reference.MNEMONIC);
			//overriding references must be primary to be active
			currentProgram.getReferenceManager().setPrimary(ref, true);
		}

		//TODO
		//finally, open the appropriate data type archive and apply its function data types
		//to the new system call space, so that the system calls have the correct signatures
		/*
		AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(currentProgram);
		DataTypeManagerService service = mgr.getDataTypeManagerService();
		List<DataTypeManager> dataTypeManagers = new ArrayList<>();
		dataTypeManagers.add(service.openDataTypeArchive(datatypeArchiveName));
		dataTypeManagers.add(currentProgram.getDataTypeManager());
		ApplyFunctionDataTypesCmd cmd = new ApplyFunctionDataTypesCmd(dataTypeManagers,
			new AddressSet(syscallSpace.getMinAddress(), syscallSpace.getMaxAddress()),
			SourceType.USER_DEFINED, false, false);
		cmd.applyTo(currentProgram);
		*/
	}

	//TODO: better error checking!
	private Map<Long, String> getSyscallNumberMap() {
		Map<Long, String> syscallMap = new HashMap<>();
		ResourceFile rFile = Application.findDataFileInAnyModule(syscallFileName);
		if (rFile == null) {
			popup("Error opening syscall number file, using default names");
			return syscallMap;
		}
		try (FileReader fReader = new FileReader(rFile.getFile(false));
				BufferedReader bReader = new BufferedReader(fReader)) {
			String line = null;
			while ((line = bReader.readLine()) != null) {
				//lines starting with # are comments
				if (!line.startsWith("#")) {
					String[] parts = line.trim().split(" ");
					Long number = Long.parseLong(parts[0]);
					syscallMap.put(number, parts[1]);
				}
			}
		}
		catch (IOException e) {
			Msg.showError(this, null, "Error reading syscall map file", e.getMessage(), e);
		}
		return syscallMap;
	}

	/**
	 * Scans through all of the functions defined in {@code program} and returns
	 * a map which takes a function to the set of address in its body which contain
	 * system calls
	 * @param program program containing functions
	 * @param tMonitor monitor
	 * @return map function -> addresses in function containing syscalls
	 * @throws CancelledException if the user cancels
	 */
	private Map<Function, Set<Address>> getSyscallsInFunctions(Program program,
			TaskMonitor tMonitor) throws CancelledException {
		Map<Function, Set<Address>> funcsToCalls = new HashMap<>();
		for (Function func : program.getFunctionManager().getFunctionsNoStubs(true)) {
			tMonitor.checkCanceled();
			for (Instruction inst : program.getListing().getInstructions(func.getBody(), true)) {
				if (tester.test(inst)) {
					Set<Address> callSites = funcsToCalls.get(func);
					if (callSites == null) {
						callSites = new HashSet<>();
						funcsToCalls.put(func, callSites);
					}
					callSites.add(inst.getAddress());
				}
			}
		}
		return funcsToCalls;
	}

	/**
	 * Uses the symbolic propogator (sic) to attempt to determine the constant value in
	 * the syscall register at each system call instruction
	 * 
	 * @param funcsToCalls map from functions containing syscalls to address in each function of 
	 * the system call
	 * @param program containing the functions
	 * @return map from addresses of system calls to system call numbers
	 * @throws CancelledException if the user cancels
	 */
	private Map<Address, Long> resolveConstants(Map<Function, Set<Address>> funcsToCalls,
			Program program, TaskMonitor tMonitor) throws CancelledException {
		Map<Address, Long> addressesToSyscalls = new HashMap<>();
		Register syscallReg = program.getLanguage().getRegister(syscallRegister);
		for (Function func : funcsToCalls.keySet()) {
			Address start = func.getEntryPoint();
			ContextEvaluator eval = new ConstantPropagationContextEvaluator(true);
			SymbolicPropogator symEval = new SymbolicPropogator(program);
			symEval.flowConstants(start, func.getBody(), eval, true, tMonitor);
			for (Address callSite : funcsToCalls.get(func)) {
				Value val = symEval.getRegisterValue(callSite, syscallReg);
				if (val == null) {
					createBookmark(callSite, "System Call",
						"Couldn't resolve value of " + syscallReg);
					printf("Couldn't resolve value of " + syscallReg + " at " + callSite + "\n");
					continue;
				}
				addressesToSyscalls.put(callSite, val.getValue());
			}
		}
		return addressesToSyscalls;
	}

	/**
	 * Checks whether a MIPS N32 instruction is a system call
	 * @param inst instruction to check
	 * @return true precisely when the instruction is a system call
	 */
	private static boolean checkMipsN32Instruction(Instruction inst) {
		boolean retVal = false;
		for (PcodeOp op : inst.getPcode()) {
			if (op.getOpcode() == PcodeOp.CALLOTHER) {
				int index = (int) op.getInput(0).getOffset();
				if (inst.getProgram().getLanguage().getUserDefinedOpName(index).equals(
					SYSCALL_MIPS_CALLOTHER)) {
					retVal = true;
				}
			}
		}
		return retVal;
	}

}
