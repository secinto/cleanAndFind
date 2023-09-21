package processor

import (
	"github.com/antchfx/jsonquery"
	"os"
	"strings"
)

func GetDocumentFromFile(filename string) *jsonquery.Node {
	data, err := os.ReadFile(filename)
	if err != nil {
		log.Fatalf("Reading JSON input file failed: %s %s", err.Error(), filename)
	}
	jsonlString := ConvertJSONLtoJSON(string(data))
	jsonReader := strings.NewReader(jsonlString)
	input, err := jsonquery.Parse(jsonReader)
	if err != nil {
		log.Fatalf("Reading JSON input file failed: %s %s", err.Error(), filename)
	}

	return input
}

func GetHTTPXEntryForIPAddress(document *jsonquery.Node, ipaddress string) []SimpleHTTPXEntry {
	var entries []SimpleHTTPXEntry
	entriesForHost, error := jsonquery.QueryAll(document, "//*[host='"+ipaddress+"']")
	if error != nil {
		log.Errorf("Querying JSON error   #%v ", error)
	}
	for _, hostEntry := range entriesForHost {
		if entryValues, ok := hostEntry.Value().(map[string]interface{}); ok {
			entry := CreateSimpleHostEntryFromHTTPX(entryValues)
			entries = append(entries, entry)
		}
	}

	return entries
}

func GetDNSRecordForIPAddress(document *jsonquery.Node, ipaddress string) DNSRecord {
	entriesForHost, error := jsonquery.Query(document, "//*/a[contains(.,'"+ipaddress+"')]")

	entry := DNSRecord{}

	if error != nil {
		log.Errorf("Querying JSON error   #%v ", error)
	} else {
		if entriesForHost != nil {
			log.Debugf("Entries for host %s are # %d", ipaddress, entriesForHost.Type)
			entry = CreateSimpleDNSEntryFromDPUX(entriesForHost.Parent)
		} else {
			log.Errorf("Provided entries for host %s doesn't have a parent", ipaddress)
		}
	}
	return entry
}

func GetDNSRecordForHostname(document *jsonquery.Node, hostname string) DNSRecord {
	entriesForHost, error := jsonquery.Query(document, "//*[host='"+hostname+"']")

	entry := DNSRecord{}

	if error != nil {
		log.Errorf("Querying JSON error   #%v ", error)
	} else {
		if entriesForHost != nil {
			log.Debugf("Entries for host %s are # %d", hostname, entriesForHost.Type)
			entry = CreateSimpleDNSEntryFromDPUX(entriesForHost)
		} else {
			log.Errorf("Provided entries for host %s doesn't have a parent", hostname)
		}
	}
	return entry
}

func CreateSimpleHostEntryFromHTTPX(entryValues map[string]interface{}) SimpleHTTPXEntry {
	var entry SimpleHTTPXEntry
	if hashValues, ok := entryValues["hash"].(map[string]interface{}); ok {
		if bodyMmh3, ok := hashValues["body_mmh3"].(string); ok {
			entry.BodyHash = bodyMmh3
		}
	}

	if contentLength, ok := entryValues["content_length"].(float64); ok {
		entry.ContentLength = int(contentLength)
	}
	if statusCode, ok := entryValues["status_code"].(float64); ok {
		entry.Status = int(statusCode)
	}
	if lines, ok := entryValues["lines"].(float64); ok {
		entry.Lines = int(lines)
	}
	if words, ok := entryValues["words"].(float64); ok {
		entry.Words = int(words)
	}
	if host, ok := entryValues["host"].(string); ok {
		entry.Host = host
	}
	if title, ok := entryValues["title"].(string); ok {
		entry.Title = title
	}
	if input, ok := entryValues["input"].(string); ok {
		entry.Input = input
	}
	if url, ok := entryValues["url"].(string); ok {
		entry.URL = url
	}
	return entry
}

func CreateSimpleDNSEntryFromDPUX(record *jsonquery.Node) DNSRecord {
	var entry DNSRecord
	if entryValues, ok := record.Value().(map[string]interface{}); ok {

		var ip4Addresses []string
		var ip6Addresses []string
		var cnames []string
		host := entryValues["host"].(string)

		if entries, ok := entryValues["a"].([]interface{}); ok {
			for _, address := range entries {
				if _, ok := address.(string); ok {
					ip4Addresses = append(ip4Addresses, address.(string))
				}
			}
		} else if entry, ok := entryValues["a"].(string); ok {
			ip4Addresses = append(ip4Addresses, entry)
		}

		if entries, ok := entryValues["aaaa"].([]interface{}); ok {
			for _, address := range entries {
				if _, ok := address.(string); ok {
					ip6Addresses = append(ip6Addresses, address.(string))
				}
			}
		} else if entry, ok := entryValues["aaaa"].(string); ok {
			ip6Addresses = append(ip6Addresses, entry)
		}

		if entry, ok := entryValues["cname"].(string); ok {
			cnames = append(cnames, entry)
		} else if entries, ok := entryValues["cname"].([]interface{}); ok {
			for _, names := range entries {
				if _, ok := names.(string); ok {
					cnames = append(cnames, names.(string))
				}
			}
		}

		entry = DNSRecord{
			Host:          host,
			CNAME:         cnames,
			IPv4Addresses: ip4Addresses,
			IPv6Addresses: ip6Addresses,
		}
	} else {
		entry = DNSRecord{}
	}
	return entry
}

func GetAllRecordsForKey(document *jsonquery.Node, key string) []*jsonquery.Node {
	return getAllNodesForKey(document, key)
}

func getAllNodesForKey(document *jsonquery.Node, key string) []*jsonquery.Node {
	entries, error := jsonquery.QueryAll(document, "//*["+key+"]")

	if error != nil {
		log.Errorf("Querying JSON error   #%v ", error)
	}

	return entries
}

func getValuesFromNode(node *jsonquery.Node, key string) []string {
	var result []string

	if entryValues, ok := node.Value().(map[string]interface{}); ok {
		values, exists := entryValues[key]
		if exists {
			if entries, ok := values.([]interface{}); ok {
				for _, subValues := range entries {
					if subValue, ok := subValues.(string); ok {
						result = AppendIfMissing(result, subValue)
					}
				}
			} else {
				if entry, ok := values.(string); ok {
					result = AppendIfMissing(result, entry)
				}
			}
		}
	}
	return result
}

func getAllNodesByContains(document *jsonquery.Node, queryKey string, queryContains []string) []*jsonquery.Node {

	var results []*jsonquery.Node

	for _, query := range queryContains {
		entries, error := jsonquery.QueryAll(document, "//*/"+queryKey+"[contains(.,'"+query+"')]")

		if error != nil {
			log.Errorf("Querying JSON error   #%v ", error)
		}

		for _, entry := range entries {
			results = append(results, entry)
		}
	}

	return results
}

// {"queryKey":"query" => "key":...}
func getNodesFromSpecificQueryViaEquals(document *jsonquery.Node, queryKey string, query string) []*jsonquery.Node {
	//var result []string

	entries, error := jsonquery.QueryAll(document, "*["+queryKey+"='"+query+"']")

	if error != nil {
		log.Errorf("Querying JSON error   #%v ", error)
	}
	return entries
}
