package processor

import (
	"reflect"
	"secinto/checkfix_utils"
	"strings"
)

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
					newSlice := checkfix_utils.RemoveFromStringArray(slice, element)
					return append(newSlice, host+":"+port)
				}
			}
		}
		return append(slice, key)
	}
	return slice
}
