/*
this is a simple messagebox PE to test with
*/

package main


import (
	"github.com/carved4/go-wincall"
	"runtime"
)

func main() {
	title, _ := wincall.UTF16ptr("test title")
	message, _ := wincall.UTF16ptr("test message")
	wincall.Call("user32.dll", "MessageBoxW",
		0,
		title,
		message,
		0)
	runtime.KeepAlive(title)
	runtime.KeepAlive(message)
}