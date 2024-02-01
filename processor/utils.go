package processor

import (
	"bufio"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"sort"
	"strings"
)

var (
	client = http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}}
)

var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

func RandStringRunes(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}

func WriteToTextFileInProject(filename string, data string) {
	writeFile, err := os.Create(filename)
	if err != nil {
		log.Fatalf("failed creating file: %s", err)
	}

	dataWriter := bufio.NewWriter(writeFile)

	if err != nil {
		log.Error(err)
	}
	dataWriter.WriteString(data)
	dataWriter.Flush()
	writeFile.Close()
}

func CreateDirectoryIfNotExists(dir string) error {
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		err = os.MkdirAll(dir, 0o770)
		if err != nil {
			return err
		}
	}
	return nil
}

func ConvertStringArrayToString(stringArray []string, separator string) string {
	sort.Strings(stringArray)
	justString := strings.Join(stringArray, separator)
	return justString
}

func ExtractTLDFromString(str string) string {

	var domainTld string

	parts := strings.Split(str, ".")

	if len(parts) < 2 {
		log.Error("Invalid domain " + str)
		domainTld = str
	} else {
		if len(parts) >= 3 && (parts[len(parts)-2] == "or" || parts[len(parts)-2] == "co" || parts[len(parts)-2] == "gv") {
			domainTld = parts[len(parts)-3] + "." + parts[len(parts)-2] + "." + parts[len(parts)-1]
		} else {
			domainTld = parts[len(parts)-2] + "." + parts[len(parts)-1]
		}
	}
	return domainTld

}

func subDomainCount(host string) int {
	tldParts := strings.Split(ExtractTLDFromString(host), ".")
	parts := strings.Split(host, ".")

	return len(parts) - len(tldParts)
}

func hostnameLength(host string) int {
	parts := strings.Split(host, ".")

	return len(parts[0])
}

func getHostAndPort(input string) (string, string) {
	var host string
	var port string
	if strings.Contains(input, ":") {
		host = strings.Split(input, ":")[0]
		port = strings.Split(input, ":")[1]
	} else {
		host = input
		port = ""
	}
	return host, port
}

func AppendDuplicatesIfMissing(slice []Duplicate, key Duplicate) []Duplicate {
	if !reflect.DeepEqual(Duplicate{}, key) && key.Hostname != "" {
		for _, element := range slice {
			if element.Hostname == key.Hostname {
				log.Debugf("%s already exists in the slice.", key.Hostname)
				return slice
			}
		}
		return append(slice, key)
	}
	return slice
}

func AppendDNSRecordIfMissing(slice []DNSRecord, key DNSRecord) []DNSRecord {
	if !reflect.DeepEqual(DNSRecord{}, key) && key.Host != "" {
		for _, element := range slice {
			if element.Host == key.Host {
				log.Debugf("%s already exists in the slice.", key.Host)
				return slice
			}
		}
		return append(slice, key)
	}
	return slice
}

func AppendHTTPXEntryIfMissing(entries []SimpleHTTPXEntry, key SimpleHTTPXEntry) []SimpleHTTPXEntry {
	if !reflect.DeepEqual(SimpleHTTPXEntry{}, key) && key.Input != "" {
		if !(key == SimpleHTTPXEntry{}) {
			for _, entry := range entries {
				if key.Input == entry.Input {
					return entries
				}
			}
			return append(entries, key)
		}
	}
	return entries
}

func AppendIfMissing(slice []string, key string) []string {
	if key != "" {
		for _, element := range slice {
			if element == key {
				log.Debugf("%s already exists in the slice.", key)
				return slice
			}
		}
		return append(slice, key)
	}
	return slice
}

func AppendIfHostMissing(slice []string, key string) []string {
	if key != "" {
		for _, element := range slice {
			var host string
			port := ""
			if strings.Contains(key, ":") {
				host = strings.Split(key, ":")[0]
				port = strings.Split(key, ":")[1]
			} else {
				host = key
			}
			if strings.HasPrefix(element, host) {
				if strings.Contains(element, ":") && element == (host+":"+port) {
					log.Debugf("%s already exists in the slice.", key)
					return slice
				} else if strings.Contains(element, ":") && port == "" {
					return slice
				} else if !strings.Contains(element, ":") && port != "" {
					newSlice := RemoveFromStringArray(slice, element)
					return append(newSlice, host+":"+port)
				}
			}
		}
		return append(slice, key)
	}
	return slice
}

func AppendSliceIfMissing(slice1 []string, slice2 []string) []string {
	var slice3 []string
	if len(slice1) == 0 {
		return slice2
	}
	if len(slice2) == 0 {
		return slice1
	}

	found := false
	for _, element2 := range slice2 {
		for _, element1 := range slice1 {
			if element2 == element1 {
				found = true
				continue
			}
		}
		if found == false {
			slice3 = append(slice3, element2)
		}
		found = false
	}
	return append(slice1, slice3...)
}

func AppendSliceIfMissingExcept(slice1 []string, slice2 []string, except string) []string {
	var slice3 []string
	if len(slice1) == 0 {
		return slice2
	}
	if len(slice2) == 0 {
		return slice1
	}

	for _, element1 := range slice1 {
		if element1 != except && element1 != "" {
			slice3 = AppendIfMissing(slice3, element1)
		}
	}
	for _, element2 := range slice2 {
		if element2 != except && element2 != "" {
			slice3 = AppendIfMissing(slice3, element2)
		}
	}
	return slice3
}

func ExistsInStringArray(slice []string, key string) bool {
	for _, element := range slice {
		if element == key {
			return true
		}
	}
	return false
}

func RemoveFromStringArray(slice []string, key string) []string {
	var newSlice []string
	for _, element := range slice {
		if !strings.HasPrefix(element, key) {
			newSlice = append(newSlice, element)
		} else {
			log.Debugf("Entry %s found in array, will be removed", key)
		}
	}
	return newSlice
}

func GetHostURL(str string) string {
	u, err := url.Parse(str)
	if err != nil {
		return str
	}
	return u.Scheme + "://" + u.Host
}

func ConvertJSONLtoJSON(input string) string {

	var data []byte
	data = append(data, '[')

	lines := strings.Split(strings.ReplaceAll(input, "\r\n", "\n"), "\n")

	isFirst := true
	for _, line := range lines {
		if !isFirst && strings.TrimSpace(line) != "" {
			data = append(data, ',')
			data = append(data, '\n')
		}
		if strings.TrimSpace(line) != "" {
			data = append(data, line...)
		}
		isFirst = false
	}
	data = append(data, ']')
	return string(data)
}

func CheckIfFileExists(path string, stopRunning bool) bool {
	_, err := os.Stat(path)
	if os.IsNotExist(err) {
		if stopRunning == true {
			log.Fatal("File " + path + " does not exist!")
			return false
		} else {
			log.Info("File " + path + " does not exist!")
			return false
		}
	}
	if err != nil {
		log.Fatal("Error checking file:", err)
		return false
	}

	return true
}

func ReadTxtFileLines(path string) []string {
	var lines []string
	f, err := os.OpenFile(path, os.O_RDONLY, os.ModePerm)
	if err != nil {
		log.Fatalf("open file error: %v", err)
		return []string{}
	}
	defer f.Close()

	rd := bufio.NewReader(f)
	for {
		line, err := rd.ReadString('\n')
		line = strings.TrimSuffix(line, "\n")
		line = strings.TrimSuffix(line, "\r")
		if err != nil {
			if err == io.EOF {
				line = strings.TrimSpace(line)
				if len(line) > 0 {
					lines = append(lines, line) // GET the line string
				}
				break
			}

			log.Fatalf("read file line error: %v", err)
			return []string{}
		}
		line = strings.TrimSpace(line)
		if len(line) > 0 {
			lines = append(lines, line) // GET the line string
		}

	}

	return lines
}
