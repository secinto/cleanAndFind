package processor

import (
	"reflect"
	utils "secinto/checkfix_utils"
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
				combineDNSRecord(element, key)
				return slice
			}
		}
		return append(slice, key)
	}
	return slice
}

func combineDNSRecord(persistentEntry DNSRecord, record DNSRecord) {
	persistentEntry.CNAME = utils.AppendIfMissingAll(persistentEntry.CNAME, record.CNAME...)
	persistentEntry.IPv4Addresses = utils.AppendIfMissingAll(persistentEntry.IPv4Addresses, record.IPv4Addresses...)
	persistentEntry.IPv6Addresses = utils.AppendIfMissingAll(persistentEntry.IPv6Addresses, record.IPv6Addresses...)
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
					newSlice := utils.RemoveFromStringArray(slice, element)
					return append(newSlice, host+":"+port)
				}
			}
		}
		return append(slice, key)
	}
	return slice
}
func ExtractTLDAndSubdomainFromString(str string) (string, string) {

	var tld string
	var subdomain string
	parts := strings.Split(str, ".")

	if len(parts) < 2 {
		log.Error("Invalid domain " + str)
		tld = str
	} else {
		if len(parts) >= 3 && (parts[len(parts)-2] == "or" || parts[len(parts)-2] == "co" || parts[len(parts)-2] == "ac" || parts[len(parts)-2] == "gv") {
			tld = parts[len(parts)-3] + "." + parts[len(parts)-2] + "." + parts[len(parts)-1]
			subdomain = strings.Join(parts[0:len(parts)-3], ".")
		} else {
			tld = parts[len(parts)-2] + "." + parts[len(parts)-1]
			subdomain = strings.Join(parts[0:len(parts)-2], ".")
		}
	}
	return tld, subdomain

}

func removeWhitespaces(entry string) string {
	entry = strings.Replace(entry, "    ", " ", -1)
	entry = strings.Replace(entry, "   ", " ", -1)
	return strings.Replace(entry, "  ", " ", -1)
}
