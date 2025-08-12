/*
generator allows for the embedding of any PE file within a valid sized .mp3, .pdf, .png, or .jpeg file
the resulting file will still be viewable in any standard media viewer, PDF reader, or audio processor
the payload itself is AES encrypted and should be decrypted via pkg/decrypt Decrypt() func after extaction
via pkg/extract Extract() func
usage:
go run generator.go -file <host_file> -pe <pe_file>
*/

package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"flag"
	"fmt"
	"image"
	"image/jpeg"
	"image/png"
	"io"
	"io/ioutil"
	"log"
	"path/filepath"
	"strings"
	"github.com/bogem/id3v2"
	"github.com/pdfcpu/pdfcpu/pkg/api"
)

var MAGIC_HEADER = []byte{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE}

type Format int

const (
	FormatPNG Format = iota
	FormatJPEG
	FormatMP3
	FormatPDF
)

var (
	hostFilename string
	peFilename   string
)

func main() {
	flag.StringVar(&hostFilename, "file", "", "Path to the host file (.mp3, .jpeg/.jpg, or .pdf)")
	flag.StringVar(&peFilename, "pe", "", "Path to the PE file to encrypt and embed")
	flag.Parse()
	
	if hostFilename == "" {
		log.Fatal("Please provide a host file path using -file flag")
	}
	if peFilename == "" {
		log.Fatal("Please provide a PE file path using -pe flag")
	}

	pebytes, err := ioutil.ReadFile(peFilename)
	if err != nil {
		log.Fatalf("Failed to read PE file: %v", err)
	}

	password, err := keygen()
	if err != nil {
		log.Fatalf("keygen failed with %v", err)
	}
	
	encryptedData, err := encryptPE(pebytes, password)
	if err != nil {
		log.Fatalf("Failed to encrypt PE file: %v", err)
	}

	outputFilename := getOutputFilename(hostFilename)
	err = EmbedPE(hostFilename, encryptedData, outputFilename)
	if err != nil {
		log.Fatalf("Failed to embed encrypted PE: %v", err)
	}
	
	fmt.Printf("PE file %s encrypted and embedded successfully with key: %x\n", peFilename, password)
	fmt.Printf("Output file saved as: %s\n", outputFilename)
}


func keygen() ([]byte, error) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key: %v", err)
	}
	return key, nil
}

func encryptPE(pebytes []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %v", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES-GCM AEAD: %v", err)
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %v", err)
	}

	ciphertext := aead.Seal(nonce, nonce, pebytes, nil)
	ciphertext = append(ciphertext, key...)
	return ciphertext, nil
}

func getOutputFilename(hostFilename string) string {
	ext := ""
	for i := len(hostFilename) - 1; i >= 0; i-- {
		if hostFilename[i] == '.' {
			ext = hostFilename[i:]
			hostFilename = hostFilename[:i]
			break
		}
	}
	return hostFilename + "_stego" + ext
}

func EmbedPE(hostFilePath string, encryptedPEData []byte, outputPath string) error {
	tmpFile, err := ioutil.TempFile("", "encrypted_pe_*.tmp")
	if err != nil {
		return fmt.Errorf("failed to create temporary file: %v", err)
	}
	defer tmpFile.Close()
	
	tmpPEPath := tmpFile.Name()
	defer func() {
		ioutil.WriteFile(tmpPEPath, []byte{}, 0644)
	}()
	
	if _, err := tmpFile.Write(encryptedPEData); err != nil {
		return fmt.Errorf("failed to write encrypted PE to temporary file: %v", err)
	}
	tmpFile.Close()
	
	return embedPEFromFiles(hostFilePath, tmpPEPath, outputPath)
}

func embedPEFromFiles(filePath, pePath, outputPath string) error {
	fileData, err := ioutil.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read file: %v", err)
	}

	format, err := detectFormat(fileData, filePath)
	if err != nil {
		return fmt.Errorf("unsupported file format: %v", err)
	}

	peData, err := ioutil.ReadFile(pePath)
	if err != nil {
		return fmt.Errorf("failed to read PE file: %v", err)
	}

	var outputData []byte
	var err2 error

	switch format {
	case FormatPNG:
		outputData, err2 = embedPEInImage(bytes.NewReader(fileData), peData, format)
		if err2 != nil {
			return fmt.Errorf("failed to embed PE into PNG: %v", err2)
		}
		if !isValidFile(outputData, format) {
			return fmt.Errorf("output is not valid - embedding failed")
		}

	case FormatJPEG:
		outputData, err2 = embedPEInJPEGMetadata(fileData, peData, outputPath)
		if err2 != nil {
			return fmt.Errorf("failed to embed PE into JPEG: %v", err2)
		}
		fmt.Printf("Embedded %d bytes of PE data into JPEG metadata\n", len(peData))
		return nil

	case FormatMP3:
		outputData, err2 = embedPEInMP3(filePath, peData, outputPath)
		if err2 != nil {
			return fmt.Errorf("failed to embed PE into MP3: %v", err2)
		}
		fmt.Printf("Embedded %d bytes of PE data into MP3 ID3 tag\n", len(peData))
		return nil

	case FormatPDF:
		outputData, err2 = embedPEInPDF(filePath, peData, outputPath)
		if err2 != nil {
			return fmt.Errorf("failed to embed PE into PDF: %v", err2)
		}
		fmt.Printf("Embedded %d bytes of PE data into PDF metadata\n", len(peData))
		return nil
	}

	if err := ioutil.WriteFile(outputPath, outputData, 0644); err != nil {
		return fmt.Errorf("failed to write output file: %v", err)
	}

	formatName := "PNG"
	if format == FormatJPEG {
		formatName = "JPEG"
	}
	fmt.Printf("Embedded %d bytes of PE data into %s\n", len(peData), formatName)
	return nil
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

func embedPEInImage(imgReader io.Reader, peBytes []byte, format Format) ([]byte, error) {
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

	newImg := image.NewRGBA(bounds)
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			newImg.Set(x, y, img.At(x, y))
		}
	}
	var dataBuffer bytes.Buffer
	dataBuffer.Write(MAGIC_HEADER)

	sizeBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(sizeBytes, uint32(len(peBytes)))
	dataBuffer.Write(sizeBytes)

	dataBuffer.Write(peBytes)

	dataToEmbed := dataBuffer.Bytes()

	totalPixels := width * height
	totalBitsNeeded := len(dataToEmbed) * 8
	if totalBitsNeeded > totalPixels*3 {
		return nil, fmt.Errorf("image too small to embed %d bytes of data (need %d pixels, have %d)", len(peBytes), totalBitsNeeded/3, totalPixels)
	}

	dataIndex := 0
	bitIndex := 0

	for y := 0; y < height && dataIndex < len(dataToEmbed); y++ {
		for x := 0; x < width && dataIndex < len(dataToEmbed); x++ {
			pixel := newImg.RGBAAt(x, y)

			channels := [](*uint8){&pixel.R, &pixel.G, &pixel.B}

			for _, channel := range channels {
				if dataIndex >= len(dataToEmbed) {
					break
				}

				bit := (dataToEmbed[dataIndex] >> (7 - bitIndex)) & 1

				*channel = (*channel & 0xFE) | bit

				bitIndex++
				if bitIndex == 8 {
					bitIndex = 0
					dataIndex++
				}
			}

			newImg.SetRGBA(x, y, pixel)
		}
	}

	var buf bytes.Buffer
	switch format {
	case FormatPNG:
		err = png.Encode(&buf, newImg)
	case FormatJPEG:

		err = jpeg.Encode(&buf, newImg, &jpeg.Options{Quality: 95})
	}

	if err != nil {
		return nil, fmt.Errorf("failed to encode image: %v", err)
	}

	return buf.Bytes(), nil
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

func isValidFile(data []byte, format Format) bool {
	switch format {
	case FormatPNG:
		return isValidPNG(data)
	case FormatJPEG:
		return isValidJPEG(data)
	case FormatMP3:
		return len(data) > 3 && (bytes.Equal(data[:3], []byte("ID3")) || bytes.Equal(data[:2], []byte{0xFF, 0xFB}))
	case FormatPDF:
		return len(data) > 4 && bytes.Equal(data[:4], []byte("%PDF"))
	default:
		return false
	}
}

func embedPEInMP3(mp3Path string, peBytes []byte, outputPath string) ([]byte, error) {

	originalData, err := ioutil.ReadFile(mp3Path)
	if err != nil {
		return nil, fmt.Errorf("failed to read original MP3 file: %v", err)
	}

	if err := ioutil.WriteFile(outputPath, originalData, 0644); err != nil {
		return nil, fmt.Errorf("failed to create output MP3 file: %v", err)
	}

	tag, err := id3v2.Open(outputPath, id3v2.Options{Parse: true})
	if err != nil {
		return nil, fmt.Errorf("failed to open output MP3 file: %v", err)
	}
	defer tag.Close()

	var dataBuffer bytes.Buffer
	dataBuffer.Write(MAGIC_HEADER)

	sizeBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(sizeBytes, uint32(len(peBytes)))
	dataBuffer.Write(sizeBytes)

	dataBuffer.Write(peBytes)

	dataToEmbed := dataBuffer.Bytes()

	base64Data := make([]byte, base64.StdEncoding.EncodedLen(len(dataToEmbed)))
	base64.StdEncoding.Encode(base64Data, dataToEmbed)

	commentFrame := id3v2.CommentFrame{
		Encoding:    id3v2.EncodingUTF8,
		Language:    "eng",
		Description: "STEGO",
		Text:        string(base64Data),
	}
	tag.AddCommentFrame(commentFrame)

	if err = tag.Save(); err != nil {
		return nil, fmt.Errorf("failed to save MP3 with embedded data: %v", err)
	}

	outputData, err := ioutil.ReadFile(outputPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read output file: %v", err)
	}

	return outputData, nil
}

func embedPEInPDF(pdfPath string, peBytes []byte, outputPath string) ([]byte, error) {
	originalData, err := ioutil.ReadFile(pdfPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read original PDF file: %v", err)
	}

	if err := ioutil.WriteFile(outputPath, originalData, 0644); err != nil {
		return nil, fmt.Errorf("failed to create output PDF file: %v", err)
	}

	var dataBuffer bytes.Buffer
	dataBuffer.Write(MAGIC_HEADER)

	sizeBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(sizeBytes, uint32(len(peBytes)))
	dataBuffer.Write(sizeBytes)

	dataBuffer.Write(peBytes)

	dataToEmbed := dataBuffer.Bytes()

	base64Data := make([]byte, base64.StdEncoding.EncodedLen(len(dataToEmbed)))
	base64.StdEncoding.Encode(base64Data, dataToEmbed)

	properties := map[string]string{
		"STEGO": string(base64Data),
	}

	err = api.AddPropertiesFile(outputPath, outputPath, properties, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to add metadata to PDF: %v", err)
	}

	outputData, err := ioutil.ReadFile(outputPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read output file: %v", err)
	}

	return outputData, nil
}

func embedPEInJPEGMetadata(jpegData []byte, peBytes []byte, outputPath string) ([]byte, error) {
	var dataBuffer bytes.Buffer
	dataBuffer.Write(MAGIC_HEADER)

	sizeBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(sizeBytes, uint32(len(peBytes)))
	dataBuffer.Write(sizeBytes)

	dataBuffer.Write(peBytes)

	dataToEmbed := dataBuffer.Bytes()


	base64Data := make([]byte, base64.StdEncoding.EncodedLen(len(dataToEmbed)))
	base64.StdEncoding.Encode(base64Data, dataToEmbed)


	var output bytes.Buffer
	

	output.Write(jpegData[:2]) // FFD8
	

	output.WriteByte(0xFF)
	output.WriteByte(0xFE)
	

	commentLen := len(base64Data) + 2
	output.WriteByte(byte(commentLen >> 8))
	output.WriteByte(byte(commentLen & 0xFF))
	
	output.Write(base64Data)
	
	output.Write(jpegData[2:])
	
	if err := ioutil.WriteFile(outputPath, output.Bytes(), 0644); err != nil {
		return nil, fmt.Errorf("failed to write output file: %v", err)
	}
	
	return output.Bytes(), nil
}