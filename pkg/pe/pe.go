/*
package pe is responsible for performing reflective loading of PE/DLL files from various formats entirely in memory 
*/
package pe 

import (
	"bytes"
	api "github.com/carved4/go-wincall"
	sys "github.com/carved4/go-native-syscall"
	"github.com/Binject/debug/pe"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"unsafe"
	"strings"
	"strconv"
	"runtime"
	"runtime/debug"
)
const (
	IMAGE_DIRECTORY_ENTRY_EXPORT    = 0x0
	IMAGE_DIRECTORY_ENTRY_IMPORT    = 0x1
	IMAGE_DIRECTORY_ENTRY_BASERELOC = 0x5
	DLL_PROCESS_ATTACH              = 0x1
	
	
	// Memory constants
	MEM_COMMIT     = 0x00001000
	MEM_RESERVE    = 0x00002000
	MEM_RELEASE    = 0x00008000
	PAGE_NOACCESS  = 0x01
	PAGE_EXECUTE_READWRITE = 0x40
	PAGE_READWRITE = 0x04
	PAGE_EXECUTE_READ = 0x20
	PAGE_READONLY = 0x02
	
	// SystemFunction / RtlEncryptMemory constants
	RTL_ENCRYPT_OPTION_SAME_PROCESS   = 0x01
	RTL_ENCRYPT_OPTION_CROSS_PROCESS  = 0x02
	RTL_ENCRYPT_OPTION_SAME_LOGON     = 0x04
	RTL_ENCRYPT_MEMORY_SIZE           = 0x08  // 8 bytes minimum
	
	// Thread access rights
	THREAD_SUSPEND_RESUME = 0x0002
	THREAD_ALL_ACCESS     = 0x1FFFFF
)

type ULONGLONG uint64


type IMAGE_DOS_HEADER struct {
	E_magic    uint16
	E_cblp     uint16
	E_cp       uint16
	E_crlc     uint16
	E_cparhdr  uint16
	E_minalloc uint16
	E_maxalloc uint16
	E_ss       uint16
	E_sp       uint16
	E_csum     uint16
	E_ip       uint16
	E_cs       uint16
	E_lfarlc   uint16
	E_ovno     uint16
	E_res      [4]uint16
	E_oemid    uint16
	E_oeminfo  uint16
	E_res2     [10]uint16
	E_lfanew   uint32
}

type IMAGE_OPTIONAL_HEADER64 struct {
	Magic                       uint16
	MajorLinkerVersion          uint8
	MinorLinkerVersion          uint8
	SizeOfCode                  uint32
	SizeOfInitializedData       uint32
	SizeOfUninitializedData     uint32
	AddressOfEntryPoint         uint32
	BaseOfCode                  uint32
	ImageBase                   uint64
	SectionAlignment            uint32
	FileAlignment               uint32
	MajorOperatingSystemVersion uint16
	MinorOperatingSystemVersion uint16
	MajorImageVersion           uint16
	MinorImageVersion           uint16
	MajorSubsystemVersion       uint16
	MinorSubsystemVersion       uint16
	Win32VersionValue           uint32
	SizeOfImage                 uint32
	SizeOfHeaders               uint32
	CheckSum                    uint32
	Subsystem                   uint16
	DllCharacteristics          uint16
	SizeOfStackReserve          uint64
	SizeOfStackCommit           uint64
	SizeOfHeapReserve           uint64
	SizeOfHeapCommit            uint64
	LoaderFlags                 uint32
	NumberOfRvaAndSizes         uint32

	DataDirectory [16]IMAGE_DATA_DIRECTORY
}

type IMAGE_DATA_DIRECTORY struct {
	VirtualAddress uint32
	Size           uint32
}

type IMAGE_FILE_HEADER struct {
	Machine              uint16
	NumberOfSections     uint16
	TimeDateStamp        uint32
	PointerToSymbolTable uint32
	NumberOfSymbols      uint32
	SizeOfOptionalHeader uint16
	Characteristics      uint16
}

type IMAGE_NT_HEADERS64 struct {
	Signature      uint32
	FileHeader     IMAGE_FILE_HEADER
	OptionalHeader IMAGE_OPTIONAL_HEADER64
}

type IMAGE_NT_HEADERS struct {
	Signature      uint32
	FileHeader     IMAGE_FILE_HEADER
	OptionalHeader IMAGE_OPTIONAL_HEADER64
}

type IMAGE_SECTION_HEADER struct {
	Name                 [8]byte
	VirtualSize          uint32
	VirtualAddress       uint32
	SizeOfRawData        uint32
	PointerToRawData     uint32
	PointerToRelocations uint32
	PointerToLinenumbers uint32
	NumberOfRelocations  uint16
	NumberOfLinenumbers  uint16
	Characteristics      uint32
}

type BASE_RELOCATION_BLOCK struct {
	PageAddress uint32
	BlockSize   uint32
}

type BASE_RELOCATION_ENTRY struct {
	OffsetType uint16
}

func (bre BASE_RELOCATION_ENTRY) Offset() uint16 {
	return bre.OffsetType & 0xFFF
}

func (bre BASE_RELOCATION_ENTRY) Type() uint16 {
	return (bre.OffsetType >> 12) & 0xF
}

type IMAGE_IMPORT_DESCRIPTOR struct {
	Characteristics     uint32
	TimeDateStamp       uint32
	ForwarderChain      uint32
	Name                uint32
	FirstThunk          uint32
	OriginalFirstThunk  uint32
}

type IMAGE_EXPORT_DIRECTORY struct {
	Characteristics       uint32
	TimeDateStamp         uint32
	MajorVersion          uint16
	MinorVersion          uint16
	Name                  uint32
	Base                  uint32
	NumberOfFunctions     uint32
	NumberOfNames         uint32
	AddressOfFunctions    uint32
	AddressOfNames        uint32
	AddressOfNameOrdinals uint32
}

type IMAGE_BASE_RELOCATION struct {
	VirtualAddress uint32
	SizeOfBlock    uint32
}

type ImageThunkData64 struct {
	AddressOfData uintptr
}

type ImageThunkData = ImageThunkData64
type OriginalImageThunkData = ImageThunkData64

type ImageReloc struct {
	Data uint16
}

func (r *ImageReloc) GetType() uint16 {
	return (r.Data >> 12) & 0xF
}

func (r *ImageReloc) GetOffset() uint16 {
	return r.Data & 0xFFF
}

// VEH Exception handling structures (future)
type EXCEPTION_RECORD struct {
	ExceptionCode        uint32
	ExceptionFlags       uint32
	ExceptionRecord      *EXCEPTION_RECORD
	ExceptionAddress     uintptr
	NumberParameters     uint32
	ExceptionInformation [15]uintptr
}

type EXCEPTION_POINTERS struct {
	ExceptionRecord *EXCEPTION_RECORD
	ContextRecord   *CONTEXT
}

func NtH(baseAddress uintptr) *IMAGE_NT_HEADERS {
	dosHeader := (*IMAGE_DOS_HEADER)(unsafe.Pointer(baseAddress))
	return (*IMAGE_NT_HEADERS)(unsafe.Pointer(baseAddress + uintptr(dosHeader.E_lfanew)))
}

func CstrVal(ptr unsafe.Pointer) []byte {
	var result []byte
	for i := 0; ; i++ {
		b := *(*byte)(unsafe.Pointer(uintptr(ptr) + uintptr(i)))
		if b == 0 {
			break
		}
		result = append(result, b)
	}
	return result
}

func IsMSBSet(value uintptr) bool {
	return (value & 0x8000000000000000) != 0
}

func ParseOrdinal(addressOfData uintptr) (unsafe.Pointer, string) {
	ord := uint16(addressOfData & 0xFFFF)
	return unsafe.Pointer(uintptr(ord)), fmt.Sprintf("#%d", ord)
}

func ParseFuncAddress(baseAddress uintptr, addressOfData uintptr) (unsafe.Pointer, string) {
	nameAddr := baseAddress + addressOfData + 2 // Skip hint
	nameBytes := CstrVal(unsafe.Pointer(nameAddr))
	return unsafe.Pointer(nameAddr), string(nameBytes)
}


func GetRelocTable(ntHeaders *IMAGE_NT_HEADERS) *IMAGE_DATA_DIRECTORY {
	if ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress == 0 {
		return nil
	}
	return &ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]
}

func Memcpy(dst, src uintptr, size uintptr) {
	srcSlice := (*[^uint32(0)]byte)(unsafe.Pointer(src))[:size:size]
	dstSlice := (*[^uint32(0)]byte)(unsafe.Pointer(dst))[:size:size]
	copy(dstSlice, srcSlice)
}

func Memset(ptr uintptr, value byte, size uintptr) {
	slice := (*[^uint32(0)]byte)(unsafe.Pointer(ptr))[:size:size]
	for i := range slice {
		slice[i] = value
	}
}

func Contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

type M128A struct {
	Low  uint64
	High int64
}

type CONTEXT struct {
	P1Home               uint64
	P2Home               uint64
	P3Home               uint64
	P4Home               uint64
	P5Home               uint64
	P6Home               uint64
	ContextFlags         uint32
	MxCsr                uint32
	SegCs                uint16
	SegDs                uint16
	SegEs                uint16
	SegFs                uint16
	SegGs                uint16
	SegSs                uint16
	EFlags               uint32
	Dr0                  uint64
	Dr1                  uint64
	Dr2                  uint64
	Dr3                  uint64
	Dr6                  uint64
	Dr7                  uint64
	Rax                  uint64
	Rcx                  uint64
	Rdx                  uint64
	Rbx                  uint64
	Rsp                  uint64
	Rbp                  uint64
	Rsi                  uint64
	Rdi                  uint64
	R8                   uint64
	R9                   uint64
	R10                  uint64
	R11                  uint64
	R12                  uint64
	R13                  uint64
	R14                  uint64
	R15                  uint64
	Rip                  uint64
	VectorRegister       [26]M128A
	VectorControl        uint64
	DebugControl         uint64
	LastBranchToRip      uint64
	LastBranchFromRip    uint64
	LastExceptionToRip   uint64
	LastExceptionFromRip uint64
}

type UString struct {
	Length        uint32
	MaximumLength uint32
	Buffer        *byte // This corresponds to PUCHAR in C
}


type CLIENT_ID struct {
	UniqueProcess uintptr
	UniqueThread  uintptr
}


type PROCESS_INFORMATION struct {
	HProcess    uintptr
	HThread     uintptr
	ProcessId   uint32
	ThreadId    uint32
}


type STARTUPINFO struct {
	Cb              uint32
	LpReserved      *uint16
	LpDesktop       *uint16
	LpTitle         *uint16
	X               uint32
	Y               uint32
	XSize           uint32
	YSize           uint32
	XCountChars     uint32
	YCountChars     uint32
	FillAttribute   uint32
	Flags           uint32
	ShowWindow      uint16
	CbReserved2     uint16
	LpReserved2     *byte
	HStdInput       uintptr
	HStdOutput      uintptr
	HStdError       uintptr
}
//go:nosplit
//go:noinline
func GetPEB() uintptr

func cstringAt(addr uintptr) string {
	var b []byte
	for {
		c := *(*byte)(unsafe.Pointer(addr))
		if c == 0 {
			break
		}
		b = append(b, c)
		addr++
	}
	return string(b)
}

func isForwardedExport(moduleHandle unsafe.Pointer, procAddr uintptr) bool {
	dosHeader := (*IMAGE_DOS_HEADER)(moduleHandle)
	if dosHeader.E_magic != 0x5A4D {
		return false
	}

	ntHeaders := (*IMAGE_NT_HEADERS)(unsafe.Pointer(uintptr(moduleHandle) + uintptr(dosHeader.E_lfanew)))
	if ntHeaders.Signature != 0x4550 {
		return false
	}

	exportDir := &ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
	if exportDir.VirtualAddress == 0 {
		return false
	}

	exportStart := uintptr(moduleHandle) + uintptr(exportDir.VirtualAddress)
	exportEnd := exportStart + uintptr(exportDir.Size)
	
	return procAddr >= exportStart && procAddr < exportEnd
}

func resolveForwardedExport(forwarderString string) (uintptr, error) {
	parts := strings.Split(forwarderString, ".")
	if len(parts) != 2 {
		return 0, fmt.Errorf("[ERROR] invalid forwarder string format: %s", forwarderString)
	}

	targetDLL := parts[0]
	targetFunction := parts[1]

	if !strings.HasSuffix(strings.ToLower(targetDLL), ".dll") {
		targetDLL += ".dll"
	}
	dllHandle := api.LoadLibraryW(targetDLL)

	var funcAddr uintptr
	var err error
	if strings.HasPrefix(targetFunction, "#") {
		ordinalStr := targetFunction[1:]
		ordinal, err := strconv.Atoi(ordinalStr)
		if err != nil {
			return 0, fmt.Errorf("[ERROR] invalid ordinal in forwarder: %s", targetFunction)
		}
		funcAddr, err = api.Call("kernel32.dll", "GetProcAddress", dllHandle, uintptr(ordinal))
		if err != nil {
			return 0, fmt.Errorf("[ERROR] failed to get ordinal %d from %s: %v", ordinal, targetDLL, err)
		}
	} else {
		funcNameBytes := append([]byte(targetFunction), 0)
		funcAddr, err = api.Call("kernel32.dll", "GetProcAddress", dllHandle, uintptr(unsafe.Pointer(&funcNameBytes[0])))
		if err != nil {
			return 0, fmt.Errorf("[ERROR] failed to get function %s from %s: %v", targetFunction, targetDLL, err)
		}
	}

	return funcAddr, nil
}

func checkForwardedExportByName(moduleHandle unsafe.Pointer, functionName string) (uintptr, bool) {
	dosHeader := (*IMAGE_DOS_HEADER)(moduleHandle)
	if dosHeader.E_magic != 0x5A4D {
		return 0, false
	}
	
	ntHeaders := (*IMAGE_NT_HEADERS)(unsafe.Pointer(uintptr(moduleHandle) + uintptr(dosHeader.E_lfanew)))
	if ntHeaders.Signature != 0x4550 {
		return 0, false
	}

	exportDir := &ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
	if exportDir.VirtualAddress == 0 {
		return 0, false
	}

	exportTable := (*IMAGE_EXPORT_DIRECTORY)(unsafe.Pointer(uintptr(moduleHandle) + uintptr(exportDir.VirtualAddress)))
	
	nameArray := (*[^uint32(0)]uint32)(unsafe.Pointer(uintptr(moduleHandle) + uintptr(exportTable.AddressOfNames)))
	ordinalArray := (*[^uint32(0)]uint16)(unsafe.Pointer(uintptr(moduleHandle) + uintptr(exportTable.AddressOfNameOrdinals)))
	functionArray := (*[^uint32(0)]uint32)(unsafe.Pointer(uintptr(moduleHandle) + uintptr(exportTable.AddressOfFunctions)))

	for i := uint32(0); i < exportTable.NumberOfNames; i++ {
		nameRVA := nameArray[i]
		nameAddr := uintptr(moduleHandle) + uintptr(nameRVA)
		exportName := cstringAt(nameAddr)
		
		if exportName == functionName {
			ordinal := ordinalArray[i]
			funcRVA := functionArray[ordinal]
			funcAddr := uintptr(moduleHandle) + uintptr(funcRVA)
			
			exportStart := uintptr(moduleHandle) + uintptr(exportDir.VirtualAddress)
			exportEnd := exportStart + uintptr(exportDir.Size)
			
			if funcAddr >= exportStart && funcAddr < exportEnd {
				return funcAddr, true
			}
			
			return 0, false
		}
	}
	
	return 0, false
}

func LoadPEFromBytes(peBytes []byte) error {
	if len(peBytes) == 0 {
		return fmt.Errorf("[ERROR] empty PE bytes provided")
	}
	
	return peLoader(&peBytes)
}

func LoadPEFromFile(filePath string) error {
	peBytes, err := ioutil.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("[ERROR] failed to read PE file: %v", err)
	}
	
	return LoadPEFromBytes(peBytes)
}

func LoadPEFromBytesWithThread(peBytes []byte) error {
	if len(peBytes) == 0 {
		return fmt.Errorf("[ERROR] empty PE bytes provided")
	}
	
	return peThreadLoader(&peBytes, 2) // Default 2 seconds
}

func LoadPEFromFileWithThread(filePath string) error {
	peBytes, err := ioutil.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("[ERROR] failed to read PE file: %v", err)
	}
	
	return peThreadLoader(&peBytes, 2) // Default 2 seconds
}

func LoadPEFromBytesWithThreadTimed(peBytes []byte, timeoutSeconds int) error {
	if len(peBytes) == 0 {
		return fmt.Errorf("[ERROR] empty PE bytes provided")
	}
	
	return peThreadLoader(&peBytes, timeoutSeconds)
}


func LoadPEFromFileWithThreadTimed(filePath string, timeoutSeconds int) error {
	peBytes, err := ioutil.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("[ERROR] failed to read PE file: %v", err)
	}
	
	fmt.Printf("[+] Loading %s with %d second timeout for user interaction\n", filePath, timeoutSeconds)
	return peThreadLoader(&peBytes, timeoutSeconds)
}

func fixImportAddressTable(baseAddress uintptr, peFile *pe.File) error {

	if peFile == nil {
		return fmt.Errorf("[ERROR] invalid PE file")
	}

	importDirs, _, _, err := peFile.ImportDirectoryTable()
	if err != nil {
		return fmt.Errorf("[ERROR] failed to get import directory table: %v", err)
	}

	if len(importDirs) == 0 {
		return nil
	}


	for _, importDir := range importDirs {
		dllName := importDir.DllName

		dllHandle := api.LoadLibraryW(dllName)


		firstThunk := baseAddress + uintptr(importDir.FirstThunk)
		originalThunk := baseAddress + uintptr(importDir.OriginalFirstThunk)
		if importDir.OriginalFirstThunk == 0 {
			originalThunk = firstThunk
		}

		funcCount := 0
		for {
			ftThunk := (*ImageThunkData64)(unsafe.Pointer(firstThunk))
			oftThunk := (*ImageThunkData64)(unsafe.Pointer(originalThunk))

			if ftThunk.AddressOfData == 0 {
				break
			}

			var funcNamePtr unsafe.Pointer
			var funcName string
			
			if IsMSBSet(oftThunk.AddressOfData) {
				funcNamePtr, funcName = ParseOrdinal(oftThunk.AddressOfData)
			} else {
				funcNamePtr, funcName = ParseFuncAddress(baseAddress, oftThunk.AddressOfData)
			}

			procAddr, err := api.Call("kernel32.dll", "GetProcAddress", dllHandle, uintptr(funcNamePtr))
			if err != nil {
				forwarderAddr, isForwarded := checkForwardedExportByName(unsafe.Pointer(dllHandle), funcName)
				if isForwarded {
					forwarderString := cstringAt(forwarderAddr)
					realProcAddr, err := resolveForwardedExport(forwarderString)
					if err != nil {
						return fmt.Errorf("[ERROR] failed to resolve forwarded export %s: %v", forwarderString, err)
					}
					procAddr = realProcAddr
				} else {
					return fmt.Errorf("[ERROR] failed to get proc address for %s function '%s': %v", dllName, funcName, err)
				}
			} else {
				if isForwardedExport(unsafe.Pointer(dllHandle), procAddr) {
					forwarderString := cstringAt(procAddr)
				
					realProcAddr, err := resolveForwardedExport(forwarderString)
					if err != nil {
						return fmt.Errorf("[ERROR] failed to resolve forwarded export %s: %v", forwarderString, err)
					}
					procAddr = realProcAddr
				}
			}

			ftThunk.AddressOfData = procAddr

			firstThunk += unsafe.Sizeof(ImageThunkData64{})
			originalThunk += unsafe.Sizeof(ImageThunkData64{})
			funcCount++
		}

	}
	return nil
}

func str1(a string) string {
	return a
}

func fixRelocTable(loadedAddr uintptr, perferableAddr uintptr, relocDir *IMAGE_DATA_DIRECTORY) error {
	
	if relocDir == nil {
		return fmt.Errorf("[ERROR] relocation directory is nil")
	}
	
	maxSizeOfDir := relocDir.Size
	relocBlocks := relocDir.VirtualAddress
	
	if maxSizeOfDir == 0 || relocBlocks == 0 {
		return fmt.Errorf("[ERROR] invalid relocation directory: size=%d, rva=0x%x", maxSizeOfDir, relocBlocks)
	}
	
	var relocBlockMetadata *IMAGE_BASE_RELOCATION
	relocBlockOffset := uintptr(0)
	processedBlocks := 0
	
	for ; relocBlockOffset < uintptr(maxSizeOfDir); relocBlockOffset += uintptr(relocBlockMetadata.SizeOfBlock) {
		relocBlockAddr := loadedAddr + uintptr(relocBlocks) + relocBlockOffset
		relocBlockMetadata = (*IMAGE_BASE_RELOCATION)(unsafe.Pointer(relocBlockAddr))
		
		if relocBlockMetadata.VirtualAddress == 0 || relocBlockMetadata.SizeOfBlock == 0 {
			break
		}
		
		if relocBlockMetadata.SizeOfBlock < 8 {
			return fmt.Errorf("[ERROR] invalid relocation block size: %d (minimum is 8)", relocBlockMetadata.SizeOfBlock)
		}
		
		entriesNum := (uintptr(relocBlockMetadata.SizeOfBlock) - unsafe.Sizeof(IMAGE_BASE_RELOCATION{})) / unsafe.Sizeof(ImageReloc{})
		pageStart := relocBlockMetadata.VirtualAddress
		
		relocEntryCursor := (*ImageReloc)(unsafe.Pointer(uintptr(unsafe.Pointer(relocBlockMetadata)) + unsafe.Sizeof(IMAGE_BASE_RELOCATION{})))

		processedEntries := 0
		for i := 0; i < int(entriesNum); i++ {
			relocType := relocEntryCursor.GetType()
			if relocType == 0 {
				relocEntryCursor = (*ImageReloc)(unsafe.Pointer(uintptr(unsafe.Pointer(relocEntryCursor)) + unsafe.Sizeof(ImageReloc{})))
				continue
			}

			relocationAddr := uintptr(pageStart) + loadedAddr + uintptr(relocEntryCursor.GetOffset())
			
			if relocationAddr < loadedAddr || relocationAddr >= loadedAddr+uintptr(maxSizeOfDir) {
			}
			
			if relocType == 3 {
				originalValue := *(*uint32)(unsafe.Pointer(relocationAddr))
				newValue := uint32(uintptr(originalValue) + loadedAddr - perferableAddr)
				*(*uint32)(unsafe.Pointer(relocationAddr)) = newValue
				processedEntries++
			} else if relocType == 10 { // IMAGE_REL_BASED_DIR64 (64-bit)
				originalValue := *(*uint64)(unsafe.Pointer(relocationAddr))
				newValue := uint64(uintptr(originalValue) + loadedAddr - perferableAddr)
				*(*uint64)(unsafe.Pointer(relocationAddr)) = newValue
				processedEntries++
			}
			
			relocEntryCursor = (*ImageReloc)(unsafe.Pointer(uintptr(unsafe.Pointer(relocEntryCursor)) + unsafe.Sizeof(ImageReloc{})))
		}
		
		processedBlocks++
	}
	
	if processedBlocks == 0 {
		return fmt.Errorf("[ERROR] no relocation blocks processed")
	}
	
	return nil
}

func CopySections(pefile *pe.File, image *[]byte, loc uintptr) error {
	
	for _, section := range pefile.Sections {
		if section.Size == 0 {
			continue
		}
		d, err := section.Data()
		if err != nil {
			return fmt.Errorf("[ERROR] failed to read section %s: %v", section.Name, err)
		}
		dataLen := uint32(len(d))
		dst := uint64(loc) + uint64(section.VirtualAddress)
		buf := (*[^uint32(0)]byte)(unsafe.Pointer(uintptr(dst)))
		for index := uint32(0); index < dataLen; index++ {
			buf[index] = d[index]
		}
	}

	bbuf := bytes.NewBuffer(nil)
	binary.Write(bbuf, binary.LittleEndian, pefile.COFFSymbols)
	binary.Write(bbuf, binary.LittleEndian, pefile.StringTable)
	b := bbuf.Bytes()
	blen := uint32(len(b))
	baseBuf := (*[^uint32(0)]byte)(unsafe.Pointer(uintptr(loc)))
	for index := uint32(0); index < blen; index++ {
		baseBuf[index+pefile.FileHeader.PointerToSymbolTable] = b[index]
	}

	return nil
}

func peLoader(bytes0 *[]byte) error {
	
	if len(*bytes0) < 64 {
		return fmt.Errorf("[ERROR] PE file too small (less than 64 bytes)")
	}
	
	defer runtime.UnlockOSThread()
	runtime.GC()
	runtime.GC()
	
	oldGCPercent := debug.SetGCPercent(-1)
	defer debug.SetGCPercent(oldGCPercent)
	
	pinnedBytes := make([]byte, len(*bytes0))
	copy(pinnedBytes, *bytes0)
	
	defer func() {
		runtime.KeepAlive(pinnedBytes)
		runtime.KeepAlive(bytes0)
		runtime.KeepAlive(&pinnedBytes[0])
	}()
	
	baseAddr := uintptr(unsafe.Pointer(&pinnedBytes[0]))
	
	if baseAddr == 0 {
		return fmt.Errorf("[ERROR] invalid base address")
	}
	
	tgtFile := NtH(baseAddr)
	if tgtFile == nil {
		return fmt.Errorf("[ERROR] invalid PE file - cannot parse NT headers")
	}

	peF, err := pe.NewFile(bytes.NewReader(pinnedBytes))
	if err != nil {
		return fmt.Errorf("[ERROR] failed to parse PE file: %v", err)
	}
	
	relocTable := GetRelocTable(tgtFile)
	preferableAddress := tgtFile.OptionalHeader.ImageBase

	status, err := sys.NtUnmapViewOfSection(0xffffffffffffffff, uintptr(tgtFile.OptionalHeader.ImageBase))
	if err != nil {
		// continue anyway, lazy but it could be expected
	}

	var imageBaseForPE uintptr
	regionSize := uintptr(tgtFile.OptionalHeader.SizeOfImage)
	
	imageBaseForPE = uintptr(preferableAddress)
	status, err = sys.NtAllocateVirtualMemory(0xffffffffffffffff, &imageBaseForPE, 0, &regionSize, 0x00001000|0x00002000, 0x40)

	if status != 0 && relocTable == nil {
		return fmt.Errorf("[ERROR] no relocation table and cannot load to preferred address (status: 0x%x)", status)
	}
	
	if status != 0 && relocTable != nil {
		imageBaseForPE = 0
		regionSize = uintptr(tgtFile.OptionalHeader.SizeOfImage)
		status, err = sys.NtAllocateVirtualMemory(0xffffffffffffffff, &imageBaseForPE, 0, &regionSize, 0x00001000|0x00002000, 0x40)

		if status != 0 {
			return fmt.Errorf("[ERROR] cannot allocate memory for PE (status: 0x%x, err: %v)", status, err)
		}
	}

	headersSize := tgtFile.OptionalHeader.SizeOfHeaders
	copy((*[1 << 30]byte)(unsafe.Pointer(imageBaseForPE))[:headersSize], pinnedBytes[:headersSize])
	
	mappedDosHeader := (*IMAGE_DOS_HEADER)(unsafe.Pointer(imageBaseForPE))
	mappedNtHeader := (*IMAGE_NT_HEADERS)(unsafe.Pointer(imageBaseForPE + uintptr(mappedDosHeader.E_lfanew)))
	
	if mappedNtHeader.Signature != 0x4550 {
		return fmt.Errorf("[ERROR] invalid NT Signature: 0x%x", mappedNtHeader.Signature)
	}
	
	tgtFile.OptionalHeader.ImageBase = uint64(imageBaseForPE)
	mappedNtHeader.OptionalHeader.ImageBase = uint64(imageBaseForPE)

	if err := CopySections(peF, &pinnedBytes, imageBaseForPE); err != nil {
		return fmt.Errorf("[ERROR] failed to copy sections: %v", err)
	}

	if err := fixImportAddressTable(imageBaseForPE, peF); err != nil {
		return fmt.Errorf("[ERROR] failed to fix import address table: %v", err)
	}

	if imageBaseForPE != uintptr(preferableAddress) {
		if relocTable != nil {
			if err := fixRelocTable(imageBaseForPE, uintptr(preferableAddress), (*IMAGE_DATA_DIRECTORY)(unsafe.Pointer(relocTable))); err != nil {
				return fmt.Errorf("[ERROR] failed to fix relocation table: %v", err)
			}
		}
	}
	
	entryPointRVA := mappedNtHeader.OptionalHeader.AddressOfEntryPoint
	
	startAddress := imageBaseForPE + uintptr(entryPointRVA)

	Memset(baseAddr, 0, uintptr(len(pinnedBytes)))
	
	runtime.KeepAlive(pinnedBytes)
	runtime.KeepAlive(bytes0)
	runtime.KeepAlive(&pinnedBytes[0])
	
	var threadHandle uintptr
	status, err = sys.NtCreateThreadEx(&threadHandle, 0x1FFFFF, 0, 0xffffffffffffffff, startAddress, 0, 0, 0, 0, 0, 0)
	if status != 0 {
		return fmt.Errorf("[ERROR] failed to create thread (status: 0x%x, err: %v)", status, err)
	}

	runtime.KeepAlive(pinnedBytes)
	runtime.KeepAlive(bytes0)
	runtime.KeepAlive(&pinnedBytes[0])

	status, err = sys.NtWaitForSingleObject(threadHandle, false, nil)
	if status == 0 {
	} else if status == 0x80000004 {
		status = 0
	} else if status == 0x00000102 {
		status = 0
	} else {
		return fmt.Errorf("[ERROR] thread execution failed with status: 0x%x", status)
	}
	
	runtime.KeepAlive(pinnedBytes)
	runtime.KeepAlive(bytes0)
	runtime.KeepAlive(&pinnedBytes[0])
	
	sys.NtClose(threadHandle)
	
	return nil	
}

func peThreadLoader(bytes0 *[]byte, timeoutSeconds int) error {
	
	if len(*bytes0) < 64 {
		return fmt.Errorf("[ERROR] PE file too small (less than 64 bytes)")
	}
	
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	runtime.GC()
	runtime.GC()
	
	oldGCPercent := debug.SetGCPercent(-1)
	defer debug.SetGCPercent(oldGCPercent)
	
	pinnedBytes := make([]byte, len(*bytes0))
	copy(pinnedBytes, *bytes0)
	
	defer func() {
		runtime.KeepAlive(pinnedBytes)
		runtime.KeepAlive(bytes0)
		runtime.KeepAlive(&pinnedBytes[0])
	}()
	
	baseAddr := uintptr(unsafe.Pointer(&pinnedBytes[0]))
	
	if baseAddr == 0 {
		return fmt.Errorf("[ERROR] invalid base address")
	}
	
	tgtFile := NtH(baseAddr)
	if tgtFile == nil {
		return fmt.Errorf("[ERROR] invalid PE file - cannot parse NT headers")
	}

	peF, err := pe.NewFile(bytes.NewReader(pinnedBytes))
	if err != nil {
		return fmt.Errorf("[ERROR] failed to parse PE file: %v", err)
	}
	
	relocTable := GetRelocTable(tgtFile)
	preferableAddress := tgtFile.OptionalHeader.ImageBase

	sys.NtUnmapViewOfSection(0xffffffffffffffff, uintptr(tgtFile.OptionalHeader.ImageBase))

	var imageBaseForPE uintptr
	regionSize := uintptr(tgtFile.OptionalHeader.SizeOfImage)
	
	imageBaseForPE = uintptr(preferableAddress)
	status, err := sys.NtAllocateVirtualMemory(0xffffffffffffffff, &imageBaseForPE, 0, &regionSize, 0x00001000|0x00002000, 0x40)

	if status != 0 && relocTable == nil {
		return fmt.Errorf("[ERROR] no relocation table and cannot load to preferred address (status: 0x%x)", status)
	}
	
	if status != 0 && relocTable != nil {
		imageBaseForPE = 0
		regionSize = uintptr(tgtFile.OptionalHeader.SizeOfImage)
		status, err = sys.NtAllocateVirtualMemory(0xffffffffffffffff, &imageBaseForPE, 0, &regionSize, 0x00001000|0x00002000, 0x40)

		if status != 0 {
			return fmt.Errorf("[ERROR] cannot allocate memory for PE (status: 0x%x, err: %v)", status, err)
		}
	}

	headersSize := tgtFile.OptionalHeader.SizeOfHeaders
	copy((*[1 << 30]byte)(unsafe.Pointer(imageBaseForPE))[:headersSize], pinnedBytes[:headersSize])
	
	mappedDosHeader := (*IMAGE_DOS_HEADER)(unsafe.Pointer(imageBaseForPE))
	mappedNtHeader := (*IMAGE_NT_HEADERS)(unsafe.Pointer(imageBaseForPE + uintptr(mappedDosHeader.E_lfanew)))
	
	if mappedNtHeader.Signature != 0x4550 {
		return fmt.Errorf("[ERROR] invalid NT Signature: 0x%x", mappedNtHeader.Signature)
	}
	
	tgtFile.OptionalHeader.ImageBase = uint64(imageBaseForPE)
	mappedNtHeader.OptionalHeader.ImageBase = uint64(imageBaseForPE)

	if err := CopySections(peF, &pinnedBytes, imageBaseForPE); err != nil {
		return fmt.Errorf("[ERROR] failed to copy sections: %v", err)
	}

	if err := fixImportAddressTable(imageBaseForPE, peF); err != nil {
		return fmt.Errorf("[ERROR] failed to fix import address table: %v", err)
	}

	if imageBaseForPE != uintptr(preferableAddress) {
		if relocTable != nil {
			if err := fixRelocTable(imageBaseForPE, uintptr(preferableAddress), (*IMAGE_DATA_DIRECTORY)(unsafe.Pointer(relocTable))); err != nil {
				return fmt.Errorf("[ERROR] failed to fix relocation table: %v", err)
			}
		}
	}
	
	entryPointRVA := mappedNtHeader.OptionalHeader.AddressOfEntryPoint
	startAddress := imageBaseForPE + uintptr(entryPointRVA)
	Memset(baseAddr, 0, uintptr(len(pinnedBytes)))
	
	runtime.KeepAlive(pinnedBytes)
	runtime.KeepAlive(bytes0)
	runtime.KeepAlive(&pinnedBytes[0])
	
	_, err = api.Call("kernel32.dll", "ConvertThreadToFiber", uintptr(0))
	if err != nil {
		return fmt.Errorf("[ERROR] failed to convert thread to fiber: %v", err)
	}
	
	// when i remove this it breaks but i dont think its doing anything
	peFiberAddr, err := api.Call("kernel32.dll", "CreateFiber", uintptr(0x100000), startAddress, uintptr(0))
	if err != nil {
		api.Call("kernel32.dll", "ConvertFiberToThread")
		return fmt.Errorf("[ERROR] failed to create PE fiber: %v", err)
	}
	api.Call("kernel32.dll", "DeleteFiber", peFiberAddr)
	api.Call("kernel32.dll", "ConvertFiberToThread")
	
	var threadHandle uintptr
	status, err = sys.NtCreateThreadEx(&threadHandle, 0x1FFFFF, 0, 0xffffffffffffffff, startAddress, 0, 0x1, 0, 0, 0, 0) // CREATE_SUSPENDED = 0x1
	if status != 0 {
		return fmt.Errorf("[ERROR] failed to create suspended thread (status: 0x%x, err: %v)", status, err)
	}
	
	exitFunctions := []string{"ExitProcess", "TerminateProcess", "exit", "_exit"}
	originalBytesMap := make(map[uintptr][]byte)
	
	kernel32Handle := api.LoadLibraryW("kernel32.dll")
	msvcrtHandle := api.LoadLibraryW("msvcrt.dll")
	
	for _, funcName := range exitFunctions {
		var funcAddr uintptr
		
		if funcName == "exit" || funcName == "_exit" {
			if msvcrtHandle != 0 {
				funcHash := api.GetHash(funcName)
				funcAddr = api.GetFunctionAddress(msvcrtHandle, funcHash)
			}
		} else {
			if kernel32Handle != 0 {
				funcHash := api.GetHash(funcName)
				funcAddr = api.GetFunctionAddress(kernel32Handle, funcHash)
			}
		}
		
		if funcAddr != 0 {
			originalBytes := make([]byte, 5)
			for i := 0; i < 5; i++ {
				originalBytes[i] = *(*byte)(unsafe.Pointer(funcAddr + uintptr(i)))
			}
			originalBytesMap[funcAddr] = originalBytes
			var oldProtect uint32
			api.Call("kernel32.dll", "VirtualProtect", funcAddr, uintptr(5), uintptr(0x40), uintptr(unsafe.Pointer(&oldProtect)))
			nopBytes := []byte{0xC3, 0x90, 0x90, 0x90, 0x90} // RET + NOPs
			for i, b := range nopBytes {
				*(*byte)(unsafe.Pointer(funcAddr + uintptr(i))) = b
			}
		}
	}
	
	status, err = sys.NtResumeThread(threadHandle, nil)
	if status != 0 {
		return fmt.Errorf("[ERROR] failed to resume thread (status: 0x%x)", status)
	}
	
	api.Call("kernel32.dll", "Sleep", uintptr(timeoutSeconds*1000)) // Convert seconds to milliseconds
	
	status, err = sys.NtSuspendThread(threadHandle, nil)
	if status == 0 {
		status, err = sys.NtTerminateThread(threadHandle, 0)
	} 
	
	for funcAddr, originalBytes := range originalBytesMap {
		var oldProtect uint32
		api.Call("kernel32.dll", "VirtualProtect", funcAddr, uintptr(5), uintptr(0x40), uintptr(unsafe.Pointer(&oldProtect)))
		for i, b := range originalBytes {
			*(*byte)(unsafe.Pointer(funcAddr + uintptr(i))) = b
		}
	}
	
	sys.NtClose(threadHandle)

	runtime.KeepAlive(pinnedBytes)
	runtime.KeepAlive(bytes0)
	runtime.KeepAlive(&pinnedBytes[0])
	
	return nil	
}

