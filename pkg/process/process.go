/*
package process exposes various utility functions for managing processes and threads, you can enumerate all procs,
enumerate threads, and perform other process-related operations.
*/
package process

import (
	"fmt"
	"unsafe"

	"github.com/carved4/go-wincall"
)

type ProcessEntry32 struct {
	Size              uint32
	Usage             uint32
	ProcessID         uint32
	DefaultHeapID     uintptr
	ModuleID          uint32
	Threads           uint32
	ParentProcessID   uint32
	PriorityClassBase int32
	Flags             uint32
	ExeFile           [260]uint16 // MAX_PATH in UTF-16
}

type ThreadEntry32 struct {
	Size           uint32
	Usage          uint32
	ThreadID       uint32
	OwnerProcessID uint32
	BasePriority   int32
	DeltaPriority  int32
	Flags          uint32
}


func EnumerateProcesses() error {
	dllHash := wincall.GetHash("kernel32.dll")
	moduleBase := wincall.GetModuleBase(dllHash)

	createToolhelp32SnapshotHash := wincall.GetHash("CreateToolhelp32Snapshot")
	createToolhelp32SnapshotAddr := wincall.GetFunctionAddress(moduleBase, createToolhelp32SnapshotHash)

	process32FirstHash := wincall.GetHash("Process32FirstW")
	process32FirstAddr := wincall.GetFunctionAddress(moduleBase, process32FirstHash)

	process32NextHash := wincall.GetHash("Process32NextW")
	process32NextAddr := wincall.GetFunctionAddress(moduleBase, process32NextHash)

	closeHandleHash := wincall.GetHash("CloseHandle")
	closeHandleAddr := wincall.GetFunctionAddress(moduleBase, closeHandleHash)

	snapshot, _ := wincall.CallWorker(createToolhelp32SnapshotAddr, 0x00000002, 0) // TH32CS_SNAPPROCESS
	if snapshot == 0 {
		return fmt.Errorf("CreateToolhelp32Snapshot failed")
	}
	defer wincall.CallWorker(closeHandleAddr, snapshot)

	var pe ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))

	fmt.Println("[+] Running Processes:")
	fmt.Printf("%-8s %-8s %-32s %s\n", "PID", "PPID", "Process Name", "Threads")
	fmt.Println("------------------------------------------------------------------------")

	result, _ := wincall.CallWorker(process32FirstAddr, snapshot, uintptr(unsafe.Pointer(&pe)))
	if result == 0 {
		return fmt.Errorf("Process32First failed")
	}

	processCount := 0

	for {
		processName := ""
		for i := 0; i < len(pe.ExeFile); i++ {
			if pe.ExeFile[i] == 0 {
				break
			}
			processName += string(rune(pe.ExeFile[i]))
		}


		fmt.Printf("%-8d %-8d %-32s %d\n", pe.ProcessID, pe.ParentProcessID, processName, pe.Threads)
		processCount++


		result, _ = wincall.CallWorker(process32NextAddr, snapshot, uintptr(unsafe.Pointer(&pe)))
		if result == 0 {
			break
		}
	}

	fmt.Printf("\n[+] Total processes found: %d\n", processCount)
	return nil
}

func EnumerateThreads(processID uint32) ([]ThreadEntry32, error) {
	dllHash := wincall.GetHash("kernel32.dll")
	moduleBase := wincall.GetModuleBase(dllHash)


	createToolhelp32SnapshotHash := wincall.GetHash("CreateToolhelp32Snapshot")
	createToolhelp32SnapshotAddr := wincall.GetFunctionAddress(moduleBase, createToolhelp32SnapshotHash)

	thread32FirstHash := wincall.GetHash("Thread32First")
	thread32FirstAddr := wincall.GetFunctionAddress(moduleBase, thread32FirstHash)

	thread32NextHash := wincall.GetHash("Thread32Next")
	thread32NextAddr := wincall.GetFunctionAddress(moduleBase, thread32NextHash)

	closeHandleHash := wincall.GetHash("CloseHandle")
	closeHandleAddr := wincall.GetFunctionAddress(moduleBase, closeHandleHash)


	snapshot, _ := wincall.CallWorker(createToolhelp32SnapshotAddr, 0x00000004, 0) // TH32CS_SNAPTHREAD
	if snapshot == 0 {
		return nil, fmt.Errorf("CreateToolhelp32Snapshot failed")
	}
	defer wincall.CallWorker(closeHandleAddr, snapshot)


	var te ThreadEntry32
	te.Size = uint32(unsafe.Sizeof(te))

	var threads []ThreadEntry32


	result, _ := wincall.CallWorker(thread32FirstAddr, snapshot, uintptr(unsafe.Pointer(&te)))
	if result == 0 {
		return nil, fmt.Errorf("Thread32First failed")
	}

	for {
		if te.OwnerProcessID == processID {
			threads = append(threads, te)
		}

		result, _ = wincall.CallWorker(thread32NextAddr, snapshot, uintptr(unsafe.Pointer(&te)))
		if result == 0 {
			break
		}
	}

	return threads, nil
}


func SuspendThread(threadID uint32) error {
	dllHash := wincall.GetHash("kernel32.dll")
	moduleBase := wincall.GetModuleBase(dllHash)

	openThreadHash := wincall.GetHash("OpenThread")
	openThreadAddr := wincall.GetFunctionAddress(moduleBase, openThreadHash)

	suspendThreadHash := wincall.GetHash("SuspendThread")
	suspendThreadAddr := wincall.GetFunctionAddress(moduleBase, suspendThreadHash)

	closeHandleHash := wincall.GetHash("CloseHandle")
	closeHandleAddr := wincall.GetFunctionAddress(moduleBase, closeHandleHash)


	hThread, _ := wincall.CallWorker(openThreadAddr, 0xFFFF, 0, uintptr(threadID)) // THREAD_ALL_ACCESS
	if hThread == 0 {
		return fmt.Errorf("OpenThread failed for thread ID %d", threadID)
	}
	defer wincall.CallWorker(closeHandleAddr, hThread)


	result, _ := wincall.CallWorker(suspendThreadAddr, hThread)
	if result == 0xFFFFFFFF { // INVALID_HANDLE_VALUE
		return fmt.Errorf("SuspendThread failed for thread ID %d", threadID)
	}

	return nil
}


func ResumeThread(threadID uint32) error {
	dllHash := wincall.GetHash("kernel32.dll")
	moduleBase := wincall.GetModuleBase(dllHash)

	openThreadHash := wincall.GetHash("OpenThread")
	openThreadAddr := wincall.GetFunctionAddress(moduleBase, openThreadHash)

	resumeThreadHash := wincall.GetHash("ResumeThread")
	resumeThreadAddr := wincall.GetFunctionAddress(moduleBase, resumeThreadHash)

	closeHandleHash := wincall.GetHash("CloseHandle")
	closeHandleAddr := wincall.GetFunctionAddress(moduleBase, closeHandleHash)


	hThread, _ := wincall.CallWorker(openThreadAddr, 0xFFFF, 0, uintptr(threadID)) // THREAD_ALL_ACCESS
	if hThread == 0 {
		return fmt.Errorf("OpenThread failed for thread ID %d", threadID)
	}
	defer wincall.CallWorker(closeHandleAddr, hThread)


	result, _ := wincall.CallWorker(resumeThreadAddr, hThread)
	if result == 0xFFFFFFFF { // INVALID_HANDLE_VALUE
		return fmt.Errorf("ResumeThread failed for thread ID %d", threadID)
	}

	return nil
}


func GetCurrentProcessID() uint32 {
	dllHash := wincall.GetHash("kernel32.dll")
	moduleBase := wincall.GetModuleBase(dllHash)

	getCurrentProcessIdHash := wincall.GetHash("GetCurrentProcessId")
	getCurrentProcessIdAddr := wincall.GetFunctionAddress(moduleBase, getCurrentProcessIdHash)

	processID, _ := wincall.CallWorker(getCurrentProcessIdAddr)
	return uint32(processID)
}


func GetCurrentThreadID() uint32 {
	dllHash := wincall.GetHash("kernel32.dll")
	moduleBase := wincall.GetModuleBase(dllHash)

	getCurrentThreadIdHash := wincall.GetHash("GetCurrentThreadId")
	getCurrentThreadIdAddr := wincall.GetFunctionAddress(moduleBase, getCurrentThreadIdHash)

	threadID, _ := wincall.CallWorker(getCurrentThreadIdAddr)
	return uint32(threadID)
}


func AnalyzeThreads(processID uint32) error {
	threads, err := EnumerateThreads(processID)
	if err != nil {
		return err
	}

	dllHash := wincall.GetHash("kernel32.dll")
	moduleBase := wincall.GetModuleBase(dllHash)
	
	ntdllHash := wincall.GetHash("ntdll.dll")
	ntdllBase := wincall.GetModuleBase(ntdllHash)

	openThreadHash := wincall.GetHash("OpenThread")
	openThreadAddr := wincall.GetFunctionAddress(moduleBase, openThreadHash)

	closeHandleHash := wincall.GetHash("CloseHandle")
	closeHandleAddr := wincall.GetFunctionAddress(moduleBase, closeHandleHash)

	getThreadTimesHash := wincall.GetHash("GetThreadTimes")
	getThreadTimesAddr := wincall.GetFunctionAddress(moduleBase, getThreadTimesHash)

	ntQueryInformationThreadHash := wincall.GetHash("NtQueryInformationThread")
	ntQueryInformationThreadAddr := wincall.GetFunctionAddress(ntdllBase, ntQueryInformationThreadHash)

	getModuleHandleHash := wincall.GetHash("GetModuleHandleA")
	getModuleHandleAddr := wincall.GetFunctionAddress(moduleBase, getModuleHandleHash)


	imageBase, _ := wincall.CallWorker(getModuleHandleAddr, 0)

	fmt.Printf("\n[+] Detailed Thread Analysis for Process %d:\n", processID)
	fmt.Printf("%-8s %-12s %-12s %-16s %-16s %-8s %-8s %s\n", 
		"TID", "StartAddr", "ImageBase", "CreationTime", "KernelTime", "BasePri", "DeltaPri", "Status")
	fmt.Println("--------------------------------------------------------------------------------------------------------")

	for _, thread := range threads {
		hThread, _ := wincall.CallWorker(openThreadAddr, 0x1FFFFF, 0, uintptr(thread.ThreadID)) // THREAD_ALL_ACCESS
		if hThread == 0 {
			fmt.Printf("%-8d %-12s %-12s %-16s %-16s %-8d %-8d %s\n",
				thread.ThreadID, "FAILED", "FAILED", "FAILED", "FAILED", 
				thread.BasePriority, thread.DeltaPriority, "OpenThread failed")
			continue
		}


		var startAddress, size uintptr
		wincall.CallWorker(ntQueryInformationThreadAddr, hThread, 9, // ThreadQuerySetWin32StartAddress
			uintptr(unsafe.Pointer(&startAddress)), unsafe.Sizeof(startAddress), uintptr(unsafe.Pointer(&size)))


		var creationTime, exitTime, kernelTime, userTime uint64
		wincall.CallWorker(getThreadTimesAddr, hThread, 
			uintptr(unsafe.Pointer(&creationTime)),
			uintptr(unsafe.Pointer(&exitTime)),
			uintptr(unsafe.Pointer(&kernelTime)),
			uintptr(unsafe.Pointer(&userTime)))

		wincall.CallWorker(closeHandleAddr, hThread)

		status := "External"
		if startAddress >= imageBase {
			status = "InImage"
		}

		fmt.Printf("%-8d 0x%-10x 0x%-10x %-16d %-16d %-8d %-8d %s\n",
			thread.ThreadID, startAddress, imageBase, creationTime, kernelTime,
			thread.BasePriority, thread.DeltaPriority, status)
	}

	return nil
}
