/*
extract is to be used with a payload generated from generate.go, it will automatically detect the format, 
parse it, and return the encrypted payload bytes to be decrypted. see cmd/main.go for usage pattern
*/
package extract

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"image"
	"image/jpeg"
	"image/png"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/bogem/id3v2"
	"github.com/pdfcpu/pdfcpu/pkg/api"
)

var magicHeader = []byte{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE}

type Format int

const (
	FormatPNG Format = iota
	FormatJPEG
	FormatMP3
	FormatPDF
)

func ExtractPEFromFile(filePath string) ([]byte, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %v", err)
	}
	defer file.Close()

	data, err := ioutil.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %v", err)
	}

	format, err := detectFormat(data, filePath)
	if err != nil {
		return nil, fmt.Errorf("unsupported file format: %v", err)
	}

	switch format {
	case FormatPNG, FormatJPEG:
		return ExtractPEFromImage(filePath)
	case FormatMP3:
		return ExtractPEFromMP3(filePath)
	case FormatPDF:
		return ExtractPEFromPDF(filePath)
	default:
		return nil, fmt.Errorf("unsupported file format")
	}
}

func ExtractPEFromBytes(fileData []byte) ([]byte, error) {
	format, err := detectFormat(fileData, "")
	if err != nil {
		return nil, fmt.Errorf("unsupported file format: %v", err)
	}

	switch format {
	case FormatPNG:
		return ExtractPEFromReader(bytes.NewReader(fileData), format)
		
	case FormatJPEG:
		return ExtractPEFromJPEGMetadata(fileData)
		
	case FormatMP3:
		return ExtractPEFromMP3Bytes(fileData)
		
	case FormatPDF:
		return ExtractPEFromPDFBytes(fileData)
		
	default:
		return nil, fmt.Errorf("unsupported file format")
	}
}

func ExtractPEFromReader(imgReader io.Reader, format Format) ([]byte, error) {
	var img image.Image
	var err error

	switch format {
	case FormatPNG:
		img, err = png.Decode(imgReader)
	case FormatJPEG:
		img, err = jpeg.Decode(imgReader)
	default:
		return nil, fmt.Errorf("unsupported format")
	}

	if err != nil {
		return nil, fmt.Errorf("failed to decode image: %v", err)
	}

	bounds := img.Bounds()
	width, height := bounds.Max.X, bounds.Max.Y

	rgbaImg := image.NewRGBA(bounds)
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			rgbaImg.Set(x, y, img.At(x, y))
		}
	}

	var extractedBits []uint8

	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			pixel := rgbaImg.RGBAAt(x, y)

			channels := []uint8{pixel.R, pixel.G, pixel.B}

			for _, channel := range channels {
				// Extract the LSB
				bit := channel & 1
				extractedBits = append(extractedBits, bit)
			}
		}
	}

	var extractedBytes []byte
	for i := 0; i < len(extractedBits); i += 8 {
		if i+7 >= len(extractedBits) {
			break
		}

		var b uint8
		for j := 0; j < 8; j++ {
			b |= extractedBits[i+j] << (7 - j)
		}
		extractedBytes = append(extractedBytes, b)
	}

	if len(extractedBytes) < len(magicHeader)+4 {
		return nil, fmt.Errorf("insufficient data extracted - no PE found")
	}

	actualHeader := extractedBytes[:len(magicHeader)]

	if !bytes.Equal(actualHeader, magicHeader) {
		return nil, fmt.Errorf("magic header not found - no embedded PE data")
	}

	sizeBytes := extractedBytes[len(magicHeader) : len(magicHeader)+4]
	peSize := binary.LittleEndian.Uint32(sizeBytes)

	dataStart := len(magicHeader) + 4
	if len(extractedBytes) < dataStart+int(peSize) {
		return nil, fmt.Errorf("insufficient PE data extracted")
	}

	peBytes := extractedBytes[dataStart : dataStart+int(peSize)]

	return peBytes, nil
}

func ExtractPEFromImage(imagePath string) ([]byte, error) {

	imgFile, err := os.Open(imagePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open image file: %v", err)
	}
	defer imgFile.Close()

	return ExtractPEFromReader(imgFile, FormatPNG)
}

func ExtractPEFromPDF(pdfPath string) ([]byte, error) {

	file, err := os.Open(pdfPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open PDF file: %v", err)
	}
	defer file.Close()

	properties, err := api.Properties(file, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to read PDF properties: %v", err)
	}

	base64Data, ok := properties["STEGO"]
	if !ok {
		return nil, fmt.Errorf("no embedded data found in PDF metadata")
	}

	dataBytes, err := base64.StdEncoding.DecodeString(base64Data)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64 data: %v", err)
	}

	if len(dataBytes) < len(magicHeader)+4 || !bytes.Equal(dataBytes[:len(magicHeader)], magicHeader) {
		return nil, fmt.Errorf("invalid magic header in embedded data")
	}

	if len(dataBytes) < len(magicHeader)+4 {
		return nil, fmt.Errorf("embedded data too short to contain size")
	}

	peSize := binary.LittleEndian.Uint32(dataBytes[len(magicHeader) : len(magicHeader)+4])

	if len(dataBytes) < len(magicHeader)+4+int(peSize) {
		return nil, fmt.Errorf("embedded data truncated, expected %d bytes", peSize)
	}

	peBytes := dataBytes[len(magicHeader)+4 : len(magicHeader)+4+int(peSize)]

	return peBytes, nil
}

func detectFormat(fileData []byte, filePath string) (Format, error) {
	ext := strings.ToLower(filepath.Ext(filePath))
	switch ext {
	case ".png":
		if isValidPNG(fileData) {
			return FormatPNG, nil
		}
	case ".jpg", ".jpeg":
		if isValidJPEG(fileData) {
			return FormatJPEG, nil
		}
	case ".mp3":
		if len(fileData) > 3 && (bytes.Equal(fileData[:3], []byte("ID3")) || bytes.Equal(fileData[:2], []byte{0xFF, 0xFB})) {
			return FormatMP3, nil
		}
	case ".pdf":
		if len(fileData) > 4 && bytes.Equal(fileData[:4], []byte("%PDF")) {
			return FormatPDF, nil
		}
	}

	if isValidPNG(fileData) {
		return FormatPNG, nil
	}
	if isValidJPEG(fileData) {
		return FormatJPEG, nil
	}

	if len(fileData) > 3 && (bytes.Equal(fileData[:3], []byte("ID3")) || bytes.Equal(fileData[:2], []byte{0xFF, 0xFB})) {
		return FormatMP3, nil
	}

	if len(fileData) > 4 && bytes.Equal(fileData[:4], []byte("%PDF")) {
		return FormatPDF, nil
	}

	return FormatPNG, fmt.Errorf("unsupported file format (supported: PNG, JPEG, MP3, PDF)")
}

func isValidPNG(data []byte) bool {
	reader := bytes.NewReader(data)
	_, err := png.Decode(reader)
	return err == nil
}

func isValidJPEG(data []byte) bool {
	reader := bytes.NewReader(data)
	_, err := jpeg.Decode(reader)
	return err == nil
}

func HasEmbeddedPE(filePath string) bool {
	_, err := ExtractPEFromFile(filePath)
	return err == nil
}

func HasEmbeddedPEFromBytes(fileData []byte) bool {
	_, err := ExtractPEFromBytes(fileData)
	return err == nil
}

func GetEmbeddedPESize(filePath string) (int, error) {
	peBytes, err := ExtractPEFromFile(filePath)
	if err != nil {
		return 0, err
	}
	return len(peBytes), nil
}

func ExtractPEFromMP3(mp3Path string) ([]byte, error) {
	// Open the MP3 file
	tag, err := id3v2.Open(mp3Path, id3v2.Options{Parse: true})
	if err != nil {
		return nil, fmt.Errorf("failed to open MP3 file: %v", err)
	}
	defer tag.Close()

	var base64Data string
	for _, frame := range tag.GetFrames(tag.CommonID("COMM")) {
		commentFrame, ok := frame.(id3v2.CommentFrame)
		if !ok {
			continue
		}

		if commentFrame.Description == "STEGO" {
			base64Data = commentFrame.Text
			break
		}
	}

	if base64Data == "" {
		for _, frame := range tag.GetFrames(tag.CommonID("TXXX")) {
			textFrame, ok := frame.(id3v2.UserDefinedTextFrame)
			if !ok {
				continue
			}

			if textFrame.Description == "STEGO" {
				base64Data = textFrame.Value
				break
			}
		}
	}

	if base64Data == "" {
		return nil, fmt.Errorf("no steganography data found in MP3 ID3 tags")
	}

	dataBytes, err := base64.StdEncoding.DecodeString(base64Data)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64 data: %v", err)
	}

	if len(dataBytes) < len(magicHeader)+4 {
		return nil, fmt.Errorf("insufficient data extracted - no PE found")
	}

	actualHeader := dataBytes[:len(magicHeader)]
	if !bytes.Equal(actualHeader, magicHeader) {
		return nil, fmt.Errorf("magic header not found - no embedded PE data")
	}

	sizeBytes := dataBytes[len(magicHeader) : len(magicHeader)+4]
	peSize := binary.LittleEndian.Uint32(sizeBytes)

	dataStart := len(magicHeader) + 4
	if len(dataBytes) < dataStart+int(peSize) {
		return nil, fmt.Errorf("insufficient PE data extracted")
	}

	peBytes := dataBytes[dataStart : dataStart+int(peSize)]
	return peBytes, nil
}

func ExtractPEFromMP3Bytes(mp3Data []byte) ([]byte, error) {
	reader := bytes.NewReader(mp3Data)
	tag, err := id3v2.ParseReader(reader, id3v2.Options{Parse: true})
	if err != nil {
		return nil, fmt.Errorf("failed to parse MP3 from bytes: %v", err)
	}
	defer tag.Close()

	var base64Data string
	for _, frame := range tag.GetFrames(tag.CommonID("COMM")) {
		commentFrame, ok := frame.(id3v2.CommentFrame)
		if !ok {
			continue
		}

		if commentFrame.Description == "STEGO" {
			base64Data = commentFrame.Text
			break
		}
	}

	if base64Data == "" {
		for _, frame := range tag.GetFrames(tag.CommonID("TXXX")) {
			textFrame, ok := frame.(id3v2.UserDefinedTextFrame)
			if !ok {
				continue
			}

			if textFrame.Description == "STEGO" {
				base64Data = textFrame.Value
				break
			}
		}
	}

	if base64Data == "" {
		return nil, fmt.Errorf("no steganography data found in MP3 ID3 tags")
	}

	dataBytes, err := base64.StdEncoding.DecodeString(base64Data)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64 data: %v", err)
	}

	if len(dataBytes) < len(magicHeader)+4 {
		return nil, fmt.Errorf("insufficient data extracted - no PE found")
	}

	actualHeader := dataBytes[:len(magicHeader)]
	if !bytes.Equal(actualHeader, magicHeader) {
		return nil, fmt.Errorf("magic header not found - no embedded PE data")
	}

	sizeBytes := dataBytes[len(magicHeader) : len(magicHeader)+4]
	peSize := binary.LittleEndian.Uint32(sizeBytes)

	dataStart := len(magicHeader) + 4
	if len(dataBytes) < dataStart+int(peSize) {
		return nil, fmt.Errorf("insufficient PE data extracted")
	}

	peBytes := dataBytes[dataStart : dataStart+int(peSize)]
	return peBytes, nil
}

func ExtractPEFromJPEGMetadata(jpegData []byte) ([]byte, error) {
	if len(jpegData) < 6 {
		return nil, fmt.Errorf("JPEG data too short")
	}
	
	if !bytes.Equal(jpegData[:2], []byte{0xFF, 0xD8}) {
		return nil, fmt.Errorf("invalid JPEG header")
	}
	
	if len(jpegData) < 6 || jpegData[2] != 0xFF || jpegData[3] != 0xFE {
		return nil, fmt.Errorf("expected comment marker (FFFE) not found after JPEG header, found: %x", jpegData[2:4])
	}
	
	commentLen := int(jpegData[4])<<8 | int(jpegData[5])
	
	if len(jpegData) < 4+commentLen {
		return nil, fmt.Errorf("comment data truncated, expected %d bytes, have %d", 4+commentLen, len(jpegData))
	}
	
	base64DataLen := commentLen - 2
	if base64DataLen <= 0 {
		return nil, fmt.Errorf("invalid comment length")
	}
	
	actualBase64End := 6
	for i := 6; i < len(jpegData)-1; i++ {
		if jpegData[i] == 0xFF && jpegData[i+1] != 0x00 && jpegData[i+1] != 0xFF {
			actualBase64End = i
			break
		}
	}
	
	if actualBase64End == 6 {
		actualBase64End = 6 + base64DataLen
	}
	
	actualBase64Len := actualBase64End - 6
	base64Data := jpegData[6:6+actualBase64Len]
	
	dataBytes, err := base64.StdEncoding.DecodeString(string(base64Data))
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64 data: %v", err)
	}
	
	if len(dataBytes) < len(magicHeader)+4 {
		return nil, fmt.Errorf("insufficient data extracted - no PE found")
	}
	
	actualHeader := dataBytes[:len(magicHeader)]
	if !bytes.Equal(actualHeader, magicHeader) {
		return nil, fmt.Errorf("magic header not found - no embedded PE data")
	}
	
	sizeBytes := dataBytes[len(magicHeader) : len(magicHeader)+4]
	peSize := binary.LittleEndian.Uint32(sizeBytes)
	
	dataStart := len(magicHeader) + 4
	if len(dataBytes) < dataStart+int(peSize) {
		return nil, fmt.Errorf("insufficient PE data extracted, have %d bytes, need %d", len(dataBytes)-dataStart, peSize)
	}
	
	peBytes := dataBytes[dataStart : dataStart+int(peSize)]
	return peBytes, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func ExtractPEFromPDFBytes(pdfData []byte) ([]byte, error) {
	reader := bytes.NewReader(pdfData)
	
	properties, err := api.Properties(reader, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to read PDF properties from bytes: %v", err)
	}

	base64Data, ok := properties["STEGO"]
	if !ok {
		return nil, fmt.Errorf("no embedded data found in PDF metadata")
	}

	dataBytes, err := base64.StdEncoding.DecodeString(base64Data)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64 data: %v", err)
	}

	if len(dataBytes) < len(magicHeader)+4 || !bytes.Equal(dataBytes[:len(magicHeader)], magicHeader) {
		return nil, fmt.Errorf("invalid magic header in embedded data")
	}

	if len(dataBytes) < len(magicHeader)+4 {
		return nil, fmt.Errorf("embedded data too short to contain size")
	}

	peSize := binary.LittleEndian.Uint32(dataBytes[len(magicHeader) : len(magicHeader)+4])

	if len(dataBytes) < len(magicHeader)+4+int(peSize) {
		return nil, fmt.Errorf("embedded data truncated, expected %d bytes", peSize)
	}

	peBytes := dataBytes[len(magicHeader)+4 : len(magicHeader)+4+int(peSize)]

	return peBytes, nil
}