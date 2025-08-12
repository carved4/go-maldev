/*
package pe is responsible for performing reflective loading of PE/DLL files from various formats entirely in memory 
*/
package pe

import (
	"fmt"
	"time"
	"unsafe"
)

// Windows basic types
type LIST_ENTRY struct {
	Flink uintptr
	Blink uintptr
}

type UNICODE_STRING struct {
	Length        uint16
	MaximumLength uint16
	Buffer        uintptr
}

type RTL_USER_PROCESS_PARAMETERS struct {
	MaximumLength     uint32
	Length            uint32
	Flags             uint32
	DebugFlags        uint32
	ConsoleHandle     uintptr
	ConsoleFlags      uint32
	StandardInput     uintptr
	StandardOutput    uintptr
	StandardError     uintptr
	CurrentDirectory  CURDIR
	DllPath           UNICODE_STRING
	ImagePathName     UNICODE_STRING
	CommandLine       UNICODE_STRING
	Environment       uintptr
	StartingX         uint32
	StartingY         uint32
	CountX            uint32
	CountY            uint32
	CountCharsX       uint32
	CountCharsY       uint32
	FillAttribute     uint32
	WindowFlags       uint32
	ShowWindowFlags   uint32
	WindowTitle       UNICODE_STRING
	DesktopInfo       UNICODE_STRING
	ShellInfo         UNICODE_STRING
	RuntimeData       UNICODE_STRING
	CurrentDirectories [32]RTL_DRIVE_LETTER_CURDIR
}

type CURDIR struct {
	DosPath UNICODE_STRING
	Handle  uintptr
}

type RTL_DRIVE_LETTER_CURDIR struct {
	Flags     uint16
	Length    uint16
	TimeStamp uint32
	DosPath   UNICODE_STRING
}

type LDR_DATA_TABLE_ENTRY struct {
	InLoadOrderLinks           LIST_ENTRY
	InMemoryOrderLinks         LIST_ENTRY
	InInitializationOrderLinks LIST_ENTRY
	DllBase                    uintptr
	EntryPoint                 uintptr
	SizeOfImage                uintptr
	FullDllName                UNICODE_STRING
	BaseDllName                UNICODE_STRING
	Flags                      uint32
	LoadCount                  uint16
	TlsIndex                   uint16
	HashLinks                  LIST_ENTRY
	TimeDateStamp              uint32
}

type PEB_LDR_DATA struct {
	Length                          uint32
	Initialized                     uint32
	SsHandle                        uintptr
	InLoadOrderModuleList           LIST_ENTRY
	InMemoryOrderModuleList         LIST_ENTRY
	InInitializationOrderModuleList LIST_ENTRY
}

type PEB struct {
	InheritedAddressSpace      byte
	ReadImageFileExecOptions   byte
	BeingDebugged              byte
	BitField                   byte
	Mutant                     uintptr
	ImageBaseAddress           uintptr
	Ldr                        *PEB_LDR_DATA
	ProcessParameters          *RTL_USER_PROCESS_PARAMETERS
	SubSystemData              uintptr
	ProcessHeap                uintptr
	FastPebLock                uintptr
	AtlThunkSListPtr           uintptr
	IFEOKey                    uintptr
	CrossProcessFlags          uint32
	KernelCallbackTable        uintptr
	SystemReserved             uint32
	AtlThunkSListPtr32         uint32
	ApiSetMap                  uintptr
	TlsExpansionCounter        uint32
	TlsBitmap                  uintptr
	TlsBitmapBits              [2]uint32
	ReadOnlySharedMemoryBase   uintptr
	SharedData                 uintptr
	ReadOnlyStaticServerData   uintptr
	AnsiCodePageData           uintptr
	OemCodePageData            uintptr
	UnicodeCaseTableData       uintptr
	NumberOfProcessors         uint32
	NtGlobalFlag               uint32
	CriticalSectionTimeout     int64
	HeapSegmentReserve         uintptr
	HeapSegmentCommit          uintptr
	HeapDeCommitTotalFreeThreshold uintptr
	HeapDeCommitFreeBlockThreshold uintptr
	NumberOfHeaps              uint32
	MaximumNumberOfHeaps       uint32
	ProcessHeaps               uintptr
	GdiSharedHandleTable       uintptr
	ProcessStarterHelper       uintptr
	GdiDCAttributeList         uint32
	LoaderLock                 uintptr
	OSMajorVersion             uint32
	OSMinorVersion             uint32
	OSBuildNumber              uint16
	OSCSDVersion               uint16
	OSPlatformId               uint32
	ImageSubsystem             uint32
	ImageSubsystemMajorVersion uint32
	ImageSubsystemMinorVersion uint32
	ActiveProcessAffinityMask  uintptr
	GdiHandleBuffer            [60]uint32
	PostProcessInitRoutine     uintptr
	TlsExpansionBitmap         uintptr
	TlsExpansionBitmapBits     [32]uint32
	SessionId                  uint32
	AppCompatFlags             uint64
	AppCompatFlagsUser         uint64
	pShimData                  uintptr
	AppCompatInfo              uintptr
	CSDVersion                 UNICODE_STRING
	ActivationContextData      uintptr
	ProcessAssemblyStorageMap  uintptr
	SystemDefaultActivationContextData uintptr
	SystemAssemblyStorageMap   uintptr
	MinimumStackCommit         uintptr
	FlsCallback                uintptr
	FlsListHead                LIST_ENTRY
	FlsBitmap                  uintptr
	FlsBitmapBits              [4]uint32
	FlsHighIndex               uint32
	WerRegistrationData        uintptr
	WerShipAssertPtr           uintptr
	pUnused                    uintptr
	pImageHeaderHash           uintptr
	TracingFlags               uint32
	CsrServerReadOnlySharedMemoryBase uint64
	TppWorkerpListLock         uintptr
	TppWorkerpList             LIST_ENTRY
	WaitOnAddressHashTable     [128]uintptr
	TelemetryCoverageHeader    uintptr
	CloudFileFlags             uint32
	CloudFileDiagFlags         uint32
	PlaceholderCompatibilityMode byte
	PlaceholderCompatibilityModeReserved [7]byte
	LeapSecondData             uintptr
	LeapSecondFlags            uint32
	NtGlobalFlag2              uint32
}


//nosplit
//noinline
func WalkLDR(ldrPtr uintptr) uintptr

//nosplit
//noinline
func GetNextModule(currentModule uintptr) uintptr

//nosplit
//noinline
func ReadModuleBase(modulePtr uintptr) uintptr

//nosplit
//noinline
func ReadModuleTimestamp(modulePtr uintptr) uint32

//nosplit
//noinline
func ReadModuleName(modulePtr uintptr) (length uint16, buffer uintptr)

func GetCurrentProcessPEB() *PEB {
	pebAddr := GetPEB()
	if pebAddr == 0 {
		return nil
	}

	maxRetries := 5
	var peb *PEB

	for i := 0; i < maxRetries; i++ {
		peb = (*PEB)(unsafe.Pointer(pebAddr))

		if peb != nil && peb.Ldr != nil {
			return peb
		}

		time.Sleep(100 * time.Millisecond)
	}

	return peb
}

func ReadUnicodeString(us UNICODE_STRING) string {
	if us.Buffer == 0 || us.Length == 0 {
		return ""
	}
	
	length := int(us.Length / 2)
	if length > 1024 {
		return "< String too long >"
	}
	
	buffer := (*[1024]uint16)(unsafe.Pointer(us.Buffer))
	result := make([]rune, 0, length)
	
	for i := 0; i < length; i++ {
		if buffer[i] == 0 {
			break
		}
		result = append(result, rune(buffer[i]))
	}
	
	return string(result)
}

func ReadEnvironmentBlock(envPtr uintptr) []string {
	if envPtr == 0 {
		return nil
	}
	
	var env []string
	ptr := envPtr
	
	for {
		var str []uint16
		for {
			char := *(*uint16)(unsafe.Pointer(ptr))
			if char == 0 {
				break
			}
			str = append(str, char)
			ptr += 2
		}
		ptr += 2
		
		if len(str) == 0 {
			break
		}
		
		runes := make([]rune, len(str))
		for i, c := range str {
			runes[i] = rune(c)
		}
		env = append(env, string(runes))
	}
	
	return env
}

func DumpPEB() {
	peb := GetCurrentProcessPEB()
	if peb == nil {
		fmt.Println("Failed to get PEB")
		return
	}
	
	fmt.Printf("InheritedAddressSpace:    %s\n", boolToYesNo(peb.InheritedAddressSpace != 0))
	fmt.Printf("ReadImageFileExecOptions: %s\n", boolToYesNo(peb.ReadImageFileExecOptions != 0))
	fmt.Printf("BeingDebugged:            %s\n", boolToYesNo(peb.BeingDebugged != 0))
	fmt.Printf("ImageBaseAddress:         %016x\n", peb.ImageBaseAddress)
	fmt.Printf("NtGlobalFlag:             %x\n", peb.NtGlobalFlag)
	fmt.Printf("NtGlobalFlag2:            %x\n", peb.NtGlobalFlag2)
	
	if peb.Ldr != nil {
		fmt.Printf("Ldr                       %016x\n", uintptr(unsafe.Pointer(peb.Ldr)))
		fmt.Printf("Ldr.Initialized:          %s\n", boolToYesNo(peb.Ldr.Initialized != 0))
		fmt.Printf("Ldr.InInitializationOrderModuleList: %016x . %016x\n", 
			peb.Ldr.InInitializationOrderModuleList.Flink, 
			peb.Ldr.InInitializationOrderModuleList.Blink)
		fmt.Printf("Ldr.InLoadOrderModuleList:           %016x . %016x\n", 
			peb.Ldr.InLoadOrderModuleList.Flink, 
			peb.Ldr.InLoadOrderModuleList.Blink)
		fmt.Printf("Ldr.InMemoryOrderModuleList:         %016x . %016x\n", 
			peb.Ldr.InMemoryOrderModuleList.Flink, 
			peb.Ldr.InMemoryOrderModuleList.Blink)
		
		fmt.Printf("        Base TimeStamp                     Module\n")
		walkModuleList(peb.Ldr)
	}
	
	fmt.Printf("SubSystemData:     %016x\n", peb.SubSystemData)
	fmt.Printf("ProcessHeap:       %016x\n", peb.ProcessHeap)
	
	if peb.ProcessParameters != nil {
		params := peb.ProcessParameters
		fmt.Printf("ProcessParameters: %016x\n", uintptr(unsafe.Pointer(params)))
		
		currentDir := ReadUnicodeString(params.CurrentDirectory.DosPath)
		if currentDir == "" {
			currentDir = "< Name not readable >"
		}
		fmt.Printf("CurrentDirectory:  '%s'\n", currentDir)
		
		windowTitle := ReadUnicodeString(params.WindowTitle)
		if windowTitle == "" {
			windowTitle = "< Name not readable >"
		}
		fmt.Printf("WindowTitle:  '%s'\n", windowTitle)
		
		imageFile := ReadUnicodeString(params.ImagePathName)
		if imageFile == "" {
			imageFile = "< Name not readable >"
		}
		fmt.Printf("ImageFile:    '%s'\n", imageFile)
		
		commandLine := ReadUnicodeString(params.CommandLine)
		if commandLine == "" {
			commandLine = "< Name not readable >"
		}
		fmt.Printf("CommandLine:  '%s'\n", commandLine)
		
		dllPath := ReadUnicodeString(params.DllPath)
		if dllPath == "" {
			dllPath = "< Name not readable >"
		}
		fmt.Printf("DllPath:      '%s'\n", dllPath)
		
		fmt.Printf("Environment:  %016x\n", params.Environment)
		if params.Environment != 0 {
			envVars := ReadEnvironmentBlock(params.Environment)
			for _, env := range envVars {
				fmt.Printf("    %s\n", env)
			}
		}
	}
}

func walkModuleList(ldr *PEB_LDR_DATA) {
	if ldr == nil {
		return
	}
	
	current := WalkLDR(uintptr(unsafe.Pointer(ldr)))
	head := uintptr(unsafe.Pointer(&ldr.InLoadOrderModuleList))
	maxIterations := 100
	
	for i := 0; i < maxIterations && current != 0 && current != head; i++ {
		moduleBase := ReadModuleBase(current)
		if moduleBase != 0 {
			timestamp := ReadModuleTimestamp(current)
			timestampStr := time.Unix(int64(timestamp), 0).Format("Jan 02 15:04:05 2006")
			if timestamp == 0 {
				timestampStr = "Dec 31 16:00:00 1969"
			}
			
			length, buffer := ReadModuleName(current)
			var moduleName string
			if length > 0 && buffer != 0 {
				moduleName = readUnicodeFromBuffer(buffer, length)
			}
			if moduleName == "" {
				moduleName = "< Name not readable >"
			}
			
			fmt.Printf("      %8x %08x %s %s\n", 
				moduleBase, 
				timestamp,
				timestampStr,
				moduleName)
		}
		
		current = GetNextModule(current)
	}
}

func readUnicodeFromBuffer(buffer uintptr, length uint16) string {
	if buffer == 0 || length == 0 {
		return ""
	}
	
	wcharCount := int(length / 2)
	if wcharCount > 512 {
		return "< String too long >"
	}
	
	wchars := (*[512]uint16)(unsafe.Pointer(buffer))
	result := make([]rune, 0, wcharCount)
	
	for i := 0; i < wcharCount; i++ {
		if wchars[i] == 0 {
			break
		}
		result = append(result, rune(wchars[i]))
	}
	
	return string(result)
}

func boolToYesNo(b bool) string {
	if b {
		return "Yes"
	}
	return "No"
}