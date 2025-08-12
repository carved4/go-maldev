/*
package pe is responsible for performing reflective loading of PE/DLL files from various formats entirely in memory 
*/
package pe

import (
	"encoding/binary"
	"fmt"
	"log"
	"strconv"
	"io/ioutil"
	"unsafe"
	api "github.com/carved4/go-wincall"
)


func uintptrToBytes(ptr uintptr) []byte {
	ptrPtr := unsafe.Pointer(&ptr)

	byteSlice := make([]byte, unsafe.Sizeof(ptr))
	for i := 0; i < int(unsafe.Sizeof(ptr)); i++ {
		byteSlice[i] = *(*byte)(unsafe.Pointer(uintptr(ptrPtr) + uintptr(i)))
	}

	return byteSlice
}

func bytePtrToString(ptr *byte) string {
	if ptr == nil {
		return ""
	}
	
	var result []byte
	for i := uintptr(0); ; i++ {
		b := *(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(ptr)) + i))
		if b == 0 {
			break
		}
		result = append(result, b)
	}
	
	return string(result)
}

func LoadDLLFromFile(filePath string, functionIdentifier interface{}) error {
	dllBytes, err := ioutil.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("[ERROR] failed to read DLL file: %v", err)
	}
	return LoadDLL(dllBytes, functionIdentifier)
}


func LoadDLL(dllBytes []byte, functionIdentifier interface{}) error {
	dllPtr := uintptr(unsafe.Pointer(&dllBytes[0]))

	// Validate minimum PE size
	if len(dllBytes) < 64 {
		return fmt.Errorf("[ERROR] DLL file too small (less than 64 bytes)")
	}

	e_lfanew := *((*uint32)(unsafe.Pointer(dllPtr + 0x3c)))
	
	// Validate e_lfanew offset
	if e_lfanew >= uint32(len(dllBytes)) || e_lfanew < 64 {
		return fmt.Errorf("[ERROR] Invalid e_lfanew offset: 0x%X", e_lfanew)
	}
	
	nt_header := (*IMAGE_NT_HEADERS64)(unsafe.Pointer(dllPtr + uintptr(e_lfanew)))
	
	// Validate NT signature
	if nt_header.Signature != 0x4550 {
		return fmt.Errorf("[ERROR] Invalid PE signature: 0x%X", nt_header.Signature)
	}

	preferredBase := uintptr(nt_header.OptionalHeader.ImageBase)
	regionSize := uintptr(nt_header.OptionalHeader.SizeOfImage)
	
	// Try to allocate at preferred base address first
	dllBase := preferredBase
	status, err := api.NtAllocateVirtualMemory(^uintptr(0), &dllBase, 0, &regionSize, 
		MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE)
	
	// If allocation at preferred address fails, try any available address
	if err != nil || status != 0 {
		dllBase = 0 // Let the system choose the address
		regionSize = uintptr(nt_header.OptionalHeader.SizeOfImage)
		status, err = api.NtAllocateVirtualMemory(^uintptr(0), &dllBase, 0, &regionSize, 
			MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE)
		if err != nil || status != 0 {
			return fmt.Errorf("[ERROR] NtAllocateVirtualMemory Failed: status=0x%X, err=%v", status, err)
		}
	}

	var numberOfBytesWritten uintptr
	status, err = api.NtWriteVirtualMemory(^uintptr(0), dllBase, uintptr(unsafe.Pointer(&dllBytes[0])), uintptr(nt_header.OptionalHeader.SizeOfHeaders), &numberOfBytesWritten)
	if err != nil || status != 0 {
		log.Fatalf("[ERROR] NtWriteVirtualMemory Failed: status=0x%X, err=%v", status, err)
	}
	numberOfSections := int(nt_header.FileHeader.NumberOfSections)

	var sectionAddr uintptr
	sectionAddr = dllPtr + uintptr(e_lfanew) + unsafe.Sizeof(nt_header.Signature) + unsafe.Sizeof(nt_header.OptionalHeader) + unsafe.Sizeof(nt_header.FileHeader)

	for i := 0; i < numberOfSections; i++ {
		section := (*IMAGE_SECTION_HEADER)(unsafe.Pointer(sectionAddr))
		sectionDestination := dllBase + uintptr(section.VirtualAddress)
		sectionBytes := (*byte)(unsafe.Pointer(dllPtr + uintptr(section.PointerToRawData)))

		status, err = api.NtWriteVirtualMemory(^uintptr(0), sectionDestination, uintptr(unsafe.Pointer(sectionBytes)), uintptr(section.SizeOfRawData), &numberOfBytesWritten)
		if err != nil || status != 0 {
			log.Fatalf("[ERROR] NtWriteVirtualMemory Failed: status=0x%X, err=%v", status, err)
		}
		sectionAddr += unsafe.Sizeof(*section)
	}

	// Process relocations only if the DLL was loaded at a different base address
	deltaImageBase := dllBase - preferredBase
	if deltaImageBase != 0 {
		relocations := nt_header.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]
		
		// Check if relocation table exists
		if relocations.VirtualAddress == 0 || relocations.Size == 0 {
			return fmt.Errorf("[ERROR] DLL loaded at different base address but no relocation table found")
		}
		
		relocation_table := dllBase + uintptr(relocations.VirtualAddress)
		var relocations_processed int = 0
		
		for relocations_processed < int(relocations.Size) {
			relocation_block := *(*BASE_RELOCATION_BLOCK)(unsafe.Pointer(relocation_table + uintptr(relocations_processed)))
			
			if relocation_block.BlockSize == 0 || relocation_block.BlockSize < 8 {
				break
			}
			
			relocEntry := relocation_table + uintptr(relocations_processed) + 8
			relocationsCount := (relocation_block.BlockSize - 8) / 2

			for i := 0; i < int(relocationsCount); i++ {
				relocationEntry := *(*BASE_RELOCATION_ENTRY)(unsafe.Pointer(relocEntry + uintptr(i*2)))
				
				if relocationEntry.Type() == 0 {
					continue
				}
				
				// Only process IMAGE_REL_BASED_DIR64 (type 10) for 64-bit
				if relocationEntry.Type() != 10 {
					continue
				}
				
				relocationRVA := relocation_block.PageAddress + uint32(relocationEntry.Offset())
				addressLocation := dllBase + uintptr(relocationRVA)
				
				// Read the current value at the relocation address
				var currentValue uint64
				byteSlice := make([]byte, 8)
				status, err := api.NtReadVirtualMemory(^uintptr(0), addressLocation, uintptr(unsafe.Pointer(&byteSlice[0])), 8, nil)
				if err != nil || status != 0 {
					return fmt.Errorf("[ERROR] Failed to read relocation at RVA 0x%X: status=0x%X, err=%v", relocationRVA, status, err)
				}
				
				currentValue = binary.LittleEndian.Uint64(byteSlice)
				newValue := currentValue + uint64(deltaImageBase)
				
				// Write the relocated value back
				binary.LittleEndian.PutUint64(byteSlice, newValue)
				status, err = api.NtWriteVirtualMemory(^uintptr(0), addressLocation, uintptr(unsafe.Pointer(&byteSlice[0])), 8, nil)
				if err != nil || status != 0 {
					return fmt.Errorf("[ERROR] Failed to write relocation at RVA 0x%X: status=0x%X, err=%v", relocationRVA, status, err)
				}
			}
			
			relocations_processed += int(relocation_block.BlockSize)
		}
	}

	importsDirectory := nt_header.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]
	importDescriptorAddr := dllBase + uintptr(importsDirectory.VirtualAddress)

	for {
		importDescriptor := *(*IMAGE_IMPORT_DESCRIPTOR)(unsafe.Pointer(importDescriptorAddr))
		if importDescriptor.Name == 0 {
			break
		}
		libraryName := uintptr(importDescriptor.Name) + dllBase
		dllName := bytePtrToString((*byte)(unsafe.Pointer(libraryName)))
		hLibrary := api.LoadLibraryW(dllName)
		if hLibrary == 0 {
			log.Fatalf("[ERROR] LoadLibrary Failed for: %s", dllName)
		}
		addr := dllBase + uintptr(importDescriptor.FirstThunk)
		for {
			thunk := *(*uint16)(unsafe.Pointer(addr))
			if thunk == 0 {
				break
			}
			functionNameAddr := dllBase + uintptr(thunk+2)

			functionName := bytePtrToString((*byte)(unsafe.Pointer(functionNameAddr)))
			functionNameBytes := append([]byte(functionName), 0) // null-terminated
			proc, err := api.Call("kernel32.dll", "GetProcAddress", hLibrary, uintptr(unsafe.Pointer(&functionNameBytes[0])))
			if err != nil || proc == 0 {
				log.Fatalf("[ERROR] Failed to GetProcAddress for %s: %v", functionName, err)
			}
			procBytes := uintptrToBytes(proc)
			var numberOfBytesWritten uintptr
			status, err := api.NtWriteVirtualMemory(^uintptr(0), addr, uintptr(unsafe.Pointer(&procBytes[0])), uintptr(len(procBytes)), &numberOfBytesWritten)
			if err != nil || status != 0 {
				log.Fatalf("[ERROR] Failed to NtWriteVirtualMemory: status=0x%X, err=%v", status, err)
			}
			addr += 0x8

		}
		importDescriptorAddr += 0x14
	}

	// Change memory protection from RW to RX now that we're done writing
	baseAddr := dllBase
	regionSize = uintptr(nt_header.OptionalHeader.SizeOfImage)
	var oldProtect uintptr
	status, err = api.NtProtectVirtualMemory(^uintptr(0), &baseAddr, &regionSize, PAGE_EXECUTE_READ, &oldProtect)
	if err != nil || status != 0 {
		log.Fatalf("[ERROR] NtProtectVirtualMemory Failed: status=0x%X, err=%v", status, err)
	}

	exportsDirectory := nt_header.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
	if exportsDirectory.VirtualAddress != 0 {
		exportTable := (*IMAGE_EXPORT_DIRECTORY)(unsafe.Pointer(dllBase + uintptr(exportsDirectory.VirtualAddress)))
		
		functionRVAs := (*[1000]uint32)(unsafe.Pointer(dllBase + uintptr(exportTable.AddressOfFunctions)))
		nameRVAs := (*[1000]uint32)(unsafe.Pointer(dllBase + uintptr(exportTable.AddressOfNames)))
		nameOrdinals := (*[1000]uint16)(unsafe.Pointer(dllBase + uintptr(exportTable.AddressOfNameOrdinals)))
		
		
		var functionRVA uint32
		var found bool

		switch v := functionIdentifier.(type) {
		case string:
			for i := uint32(0); i < exportTable.NumberOfNames; i++ {
				nameAddr := dllBase + uintptr(nameRVAs[i])
				funcName := bytePtrToString((*byte)(unsafe.Pointer(nameAddr)))
				if funcName == v {
					functionRVA = functionRVAs[nameOrdinals[i]]
					found = true
					break
				}
			}
		case int:
			ordinalIndex := uint32(v) - exportTable.Base
			if ordinalIndex < exportTable.NumberOfFunctions {
				functionRVA = functionRVAs[ordinalIndex]
				found = true
			}
		default:
			if str, ok := functionIdentifier.(string); ok {
				if num, err := strconv.Atoi(str); err == nil {
					ordinalIndex := uint32(num) - exportTable.Base
					if ordinalIndex < exportTable.NumberOfFunctions {
						functionRVA = functionRVAs[ordinalIndex]
						found = true
					}
				} else {
					for i := uint32(0); i < exportTable.NumberOfNames; i++ {
						nameAddr := dllBase + uintptr(nameRVAs[i])
						funcName := bytePtrToString((*byte)(unsafe.Pointer(nameAddr)))
						if funcName == str {
							functionRVA = functionRVAs[nameOrdinals[i]]
							found = true
							break
						}
					}
				}
			}
		}
		
		if found && functionRVA != 0 {
			api.CallWorker(dllBase+uintptr(functionRVA))
		} else {
		}
	} else {
		api.CallWorker(dllBase+uintptr(nt_header.OptionalHeader.AddressOfEntryPoint), dllBase, DLL_PROCESS_ATTACH, 0)
	}

	baseAddr = dllBase
	regionSize = 0
	return nil
}
