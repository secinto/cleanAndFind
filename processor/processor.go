package processor

import (
	"encoding/json"
	"github.com/antchfx/jsonquery"
	"golang.org/x/exp/slices"
	"gopkg.in/yaml.v3"
	"os"
	"reflect"
	"strconv"
	"strings"
)

var (
	log           = NewLogger()
	appConfig     Config
	wantedHosts   = []string{"www", "mail", "portal", "webmail", "dashboard", "login", "remote", "ssh"}
	unwantedHosts = []string{"autodiscover", "sip", "lyncdiscover", "enterpriseenrollment", "enterpriseregistration", "_dmarc", "s1._domainkey"}
)

//-------------------------------------------
//			Initialization methods
//-------------------------------------------

func NewProcessor(options *Options) (*Processor, error) {
	finder := &Processor{options: options}
	finder.initialize(options.SettingsFile)
	return finder, nil
}

func (p *Processor) initialize(configLocation string) {
	appConfig = loadConfigFrom(configLocation)
	if !strings.HasSuffix(appConfig.S2SPath, "/") {
		appConfig.S2SPath = appConfig.S2SPath + "/"
	}
	p.options.BaseFolder = appConfig.S2SPath + p.options.Project
	if !strings.HasSuffix(p.options.BaseFolder, "/") {
		p.options.BaseFolder = p.options.BaseFolder + "/"
	}
	appConfig.HttpxDomainsFile = strings.Replace(appConfig.HttpxDomainsFile, "{project_name}", p.options.Project, -1)
	appConfig.DpuxFile = strings.Replace(appConfig.DpuxFile, "{project_name}", p.options.Project, -1)
}

func loadConfigFrom(location string) Config {
	var config Config
	var yamlFile []byte
	var err error

	yamlFile, err = os.ReadFile(location)
	if err != nil {
		yamlFile, err = os.ReadFile(defaultSettingsLocation)
		if err != nil {
			log.Fatalf("yamlFile.Get err   #%v ", err)
		}
	}

	err = yaml.Unmarshal(yamlFile, &config)
	if err != nil {
		log.Fatalf("Unmarshal: %v", err)
	}

	if &config == nil {
		config = Config{
			S2SPath:          "S://",
			HttpxDomainsFile: "http_from.domains.output.json",
			DpuxFile:         "dpux.{project_name}.output.json",
			DpuxIPFile:       "dpux_clean.txt",
		}
	}

	err = yaml.Unmarshal(yamlFile, &config)
	if err != nil {
		log.Fatalf("Unmarshal: %v", err)
	}
	return config
}

//-------------------------------------------
//			Main functions methods
//-------------------------------------------

func (p *Processor) CleanAndFind() error {
	if p.options.Project != "" {
		if p.options.File != "" {
			p.CleanFile()
		} else {
			var mxRecords []MailRecord
			log.Info("Obtaining all mail DNS entries for project")
			mxRecords = p.FindMailRecords()
			log.Infof("%d Mail information records have been found", len(mxRecords))
			log.Infof("Verifying duplications of project %s", p.options.Project)
			p.CleanDomains(mxRecords)
		}
	} else {
		log.Info("No project specified. Exiting application")
	}
	return nil
}

func (p *Processor) CleanFile() {
	log.Infof("Using %s as HTTPX input file", p.options.File)
	httpxInput := GetDocumentFromFile(p.options.File)
	hostEntries := GetValuesForKey(httpxInput, "host")
	var ips []string
	if len(hostEntries) >= 1 {
		for _, hostEntry := range hostEntries {
			if value, ok := hostEntry.Value().(string); ok {
				ips = AppendIfMissing(ips, value)
			}
		}

	}
	var nonDuplicateHosts []string
	for _, ipAddress := range ips {
		cleanedHosts, _ := p.deduplicateByContent(httpxInput, ipAddress)
		for _, uniqueHost := range cleanedHosts {
			log.Debugf("Adding hostname %s to non duplicates", uniqueHost.Input)
			nonDuplicateHosts = AppendIfMissing(nonDuplicateHosts, uniqueHost.Input)
		}
	}
	WriteToTextFileInProject(p.options.UniqueHostsFile, strings.Join(nonDuplicateHosts[:], "\n"))

}

func (p *Processor) CleanDomains(mxRecords []MailRecord) {
	// Get JSON file
	var httpxInput *jsonquery.Node
	httpxInputFile := p.options.BaseFolder + "recon/" + appConfig.HttpxDomainsFile
	log.Infof("Using HTTPX domains input %s", httpxInputFile)
	httpxInput = GetDocumentFromFile(httpxInputFile)
	ipsInputFile := p.options.BaseFolder + "recon/" + appConfig.DpuxIPFile
	log.Infof("Using DPUx IP input %s", ipsInputFile)
	ipsInput := ReadTxtFileLines(ipsInputFile)

	dpuxInputFile := p.options.BaseFolder + "recon/" + appConfig.DpuxFile
	log.Infof("Using DPUx input %s", dpuxInputFile)
	dpuxInput := GetDocumentFromFile(dpuxInputFile)

	// Get Hosts from DPUX, since not every ipAddress must have HTTP services enabled, they would not be found in

	var nonDuplicateHosts []string
	var duplicateHosts []Duplicate
	var dnsRecords []DNSRecord
	// Iterate over all hosts and resolve duplicates. Use the IP as selector.
	// All identified IP addresses as resolved from DPUX are used.
	for _, ipAddress := range ipsInput {
		log.Debugf("Identifying duplicate hosts for IP %s from HTTP responses", ipAddress)
		cleanedHosts, duplicates := p.deduplicateByContent(httpxInput, ipAddress)
		if len(cleanedHosts) > 0 {
			for _, uniqueHost := range cleanedHosts {
				log.Debugf("Adding hostname %s to non duplicates", uniqueHost.Input)
				nonDuplicateHosts = AppendIfMissing(nonDuplicateHosts, uniqueHost.Input)

				host, _ := getHostAndPort(uniqueHost.Input)
				dnsEntry := GetDNSRecordForHostname(dpuxInput, host)
				if dnsEntry.Host != "" {
					dnsRecords = AppendDNSRecordIfMissing(dnsRecords, dnsEntry)
				} else {
					log.Debugf("Found DNS record with empty ipAddress during processing IP %s", ipAddress)
				}
			}
		} else {
			dnsEntry := GetDNSRecordForIPAddress(dpuxInput, ipAddress)
			if dnsEntry.Host != "" {
				log.Debugf("Adding hostname %s to non duplicates for IP %s", dnsEntry.Host, ipAddress)
				nonDuplicateHosts = AppendIfMissing(nonDuplicateHosts, dnsEntry.Host)
				dnsRecords = AppendDNSRecordIfMissing(dnsRecords, dnsEntry)
			} else {
				log.Debugf("Found DNS record with empty ipAddress during processing IP %s", ipAddress)
			}
		}
		for _, duplicateEntry := range duplicates {
			duplicateHosts = AppendDuplicatesIfMissing(duplicateHosts, duplicateEntry)
		}
	}

	for _, mailHost := range mxRecords {
		dnsEntry := GetDNSRecordForHostname(dpuxInput, mailHost.Host)
		if !reflect.DeepEqual(DNSRecord{}, dnsEntry) {
			dnsRecords = AppendDNSRecordIfMissing(dnsRecords, dnsEntry)
			nonDuplicateHosts = AppendIfMissing(nonDuplicateHosts, dnsEntry.Host)
			for _, duplicate := range duplicateHosts {
				if duplicate.Hostname == dnsEntry.Host {
					continue
				}
				duplicate.DuplicateHosts = RemoveFromStringArray(duplicate.DuplicateHosts, dnsEntry.Host)
			}
		}
	}

	var cleanedDomains []string
	var cleanedDomainsWithPorts []string

	duplicateToNonDuplicateMap := createMapNonDuplicateForDuplicate(duplicateHosts)

	for _, hostEntry := range nonDuplicateHosts {
		host, port := getHostAndPort(hostEntry)

		if !checkIfHostStringIsContained(host, unwantedHosts, "") {
			cleanedDomains = AppendIfMissing(cleanedDomains, host)
			if port != "" {
				cleanedDomainsWithPorts = AppendIfHostMissing(cleanedDomainsWithPorts, host+":"+port)
				if port == "80" {
					nonDuplicate := duplicateToNonDuplicateMap[host+":443"]
					if nonDuplicate != "" {
						cleanedDomainsWithPorts = AppendIfHostMissing(cleanedDomainsWithPorts, host+":443")
					}
				}
			} else {
				cleanedDomainsWithPorts = AppendIfHostMissing(cleanedDomainsWithPorts, host)
			}
		} else {
			log.Infof("Not using ipAddress %s", host)
		}
	}
	log.Infof("Found %d non duplicate hosts without port", len(cleanedDomains))
	cleanedDomainsString := ConvertStringArrayToString(cleanedDomains, "\n")

	WriteToTextFileInProject(p.options.BaseFolder+"domains_clean.txt", cleanedDomainsString)

	log.Infof("Found %d non duplicate hosts with port", len(cleanedDomainsWithPorts))
	cleanedDomainsWithPortsString := ConvertStringArrayToString(cleanedDomainsWithPorts, "\n")
	WriteToTextFileInProject(p.options.BaseFolder+"domains_clean_with_http_ports.txt", cleanedDomainsWithPortsString)

	data, _ := json.MarshalIndent(duplicateHosts, "", " ")
	WriteToTextFileInProject(p.options.BaseFolder+"findings/duplicates.json", string(data))

	data, _ = json.MarshalIndent(dnsRecords, "", " ")
	WriteToTextFileInProject(p.options.BaseFolder+"findings/dns_clean.json", string(data))

	log.Info("Created cleaned domains file for project")
}

func (p *Processor) FindMailRecords() []MailRecord {
	var mxRecords []MailRecord

	dpuxFile := p.options.BaseFolder + "recon/" + appConfig.DpuxFile
	log.Infof("Using DPUX DNS input %s", dpuxFile)
	input := GetDocumentFromFile(dpuxFile)

	// Get MX records for the main site (the one named as the project
	allMXRecords := GetAllRecordsForKey(input, "mx")
	// Check all other entries from DNSX
	if len(allMXRecords) >= 1 {
		// Fine, we found at least one. Now check if the other information (SPF, DMARC, DKIM) is available.
		for _, mxRecordNode := range allMXRecords {
			hostEntries := getValuesFromNode(mxRecordNode, "host")

			if len(hostEntries) >= 1 {
				mxRecordEntries := getValuesFromNode(mxRecordNode, "mx")
				mxRecord := MailRecord{
					Host:      hostEntries[0],
					MXRecords: mxRecordEntries,
				}
				// Check if the host has an SPF entry.
				txtEntries := getValuesFromNode(mxRecordNode, "txt")
				if len(txtEntries) > 0 {
					for _, txtEntry := range txtEntries {
						if strings.Contains(strings.ToLower(txtEntry), "spf") {
							mxRecord.SPFEntry = txtEntry
						}
					}
				}
				// Check if an DMARC entry exists for the current host
				dmarcEntries := getNodesFromSpecificQueryViaEquals(input, "host", "_dmarc."+hostEntries[0])
				if len(dmarcEntries) > 0 {
					dmarcEntry := getValuesFromNode(dmarcEntries[0], "txt")
					if dmarcEntry != nil {
						mxRecord.DMARCEntry = dmarcEntry[0]
					}
				}

				dkimEntries := getAllNodesByContains(input, "host", []string{"_domainkey." + hostEntries[0]})
				if len(dkimEntries) > 0 {
					var entries []string
					for _, dkimEntry := range dkimEntries {
						dkimValue := getValuesFromNode(dkimEntry.Parent, "txt")
						if len(dkimValue) > 0 {
							entries = append(entries, strings.Join(dkimValue, ""))
						}
					}
					if len(entries) > 0 {
						mxRecord.DKIMEntries = entries
					}
				}
				if !strings.HasPrefix(hostEntries[0], "_dmarc.") && !strings.Contains(hostEntries[0], "_domainkey.") {
					mxRecords = append(mxRecords, mxRecord)
				} else {
					log.Infof("Not using DNS record for %s", hostEntries[0])
				}
			} else {
				log.Errorf("Found records without host value. %s", mxRecordNode)
			}
		}
	}

	data, _ := json.MarshalIndent(mxRecords, "", " ")
	CreateDirectoryIfNotExists(p.options.BaseFolder + "findings/")
	WriteToTextFileInProject(p.options.BaseFolder+"findings/mailsecurity.json", string(data))

	return mxRecords
}

//-------------------------------------------
//			Helper methods
//-------------------------------------------

func (p *Processor) deduplicateByContent(httpxInput *jsonquery.Node, ipaddress string) ([]SimpleHTTPXEntry, map[string]Duplicate) {
	hostsOnSameIP := GetHTTPXEntryForIPAddress(httpxInput, ipaddress)
	cleanAfterHash := make(map[string]SimpleHTTPXEntry)
	// TLDs are always used, even if they are duplicates
	tlds := make(map[string]SimpleHTTPXEntry)
	duplicates := make(map[string]Duplicate)
	cleanAfterWordsAndLines := make(map[string]SimpleHTTPXEntry)
	if len(hostsOnSameIP) > 0 {
		// Finding duplicates based on the hash values for the same IP.
		log.Debugf("Checking duplicates for IP %s", ipaddress)
		for _, hostEntry := range hostsOnSameIP {
			log.Debugf("Checking hostname %s", hostEntry.Input)
			if _, ok := cleanAfterHash[hostEntry.BodyHash]; !ok {
				// TLD other than the project domain are added to tlds. If the project TLD is found
				// it is returned as best match and must be added manually. If another subdomain is found instead
				// of the project domain (not in the list) it is also returned as best match and must be added.
				// If no best match is found the current hostname is added (should only be the case when?)
				possibleDupes := getSimpleEntriesForBodyHash(hostsOnSameIP, hostEntry.BodyHash)
				if len(possibleDupes) > 1 {
					bestMatch := getBestDuplicateMatch(possibleDupes, p.options.Project, tlds)
					if (bestMatch != SimpleHTTPXEntry{}) {
						cleanAfterHash[hostEntry.BodyHash] = bestMatch
					} else {
						cleanAfterHash[hostEntry.BodyHash] = hostEntry
					}
					// Create the base entry for the duplicates. All duplicates of the bodyHash are associated with this entry
					duplicate := getDuplicate(cleanAfterHash[hostEntry.BodyHash])
					if duplicate.Hostname != hostEntry.Input {
						duplicate.DuplicateHosts = AppendIfMissing(duplicate.DuplicateHosts, hostEntry.Input)
					}
					duplicates[hostEntry.BodyHash] = duplicate
				} else {
					//Only one exists, use it
					cleanAfterHash[hostEntry.BodyHash] = hostEntry
				}
			} else {
				//All other are duplicates
				duplicate := duplicates[hostEntry.BodyHash]
				if reflect.DeepEqual(Duplicate{}, duplicate) {
					duplicate = getDuplicate(hostEntry)
				}
				if duplicate.Hostname != hostEntry.Input {
					duplicate.DuplicateHosts = AppendIfMissing(duplicate.DuplicateHosts, hostEntry.Input)
				}
				duplicates[hostEntry.BodyHash] = duplicate
			}
		}
		// Also find duplicates based on the words and lines from the HTTP response. If they are the same
		// for the same IP it is very likely that the content is the same although some minor thing changed
		// and therefore the hash changed. (Used IP, hostname or some other changes such as generated Javascript)
		// See austria-beteiligungen (hvw-wegraz.at), jaw.or.at for reasons.
		for _, hostEntry := range cleanAfterHash {
			key := strconv.Itoa(hostEntry.Words) + "-" + strconv.Itoa(hostEntry.Lines)
			if len(cleanAfterHash) > 1 {
				log.Debugf("Checking hostname %s", hostEntry.Input)
				if _, ok := cleanAfterWordsAndLines[key]; !ok {
					possibleDupes := getSimpleEntriesForMetrics(cleanAfterHash, hostEntry)
					if len(possibleDupes) > 1 {
						bestMatch := getBestDuplicateMatch(possibleDupes, p.options.Project, tlds)
						if (bestMatch != SimpleHTTPXEntry{}) {
							// Use the best match
							cleanAfterWordsAndLines[key] = bestMatch
						} else {
							// If empty, meaning no best match found, use the current one.
							cleanAfterWordsAndLines[key] = hostEntry
						}
						processDuplicate(duplicates, cleanAfterWordsAndLines[key], key)
					} else {
						//Only one entry exists, use it.
						cleanAfterWordsAndLines[key] = hostEntry
						// Create the base entry for the duplicates. All duplicates of the words and lines are associated with this entry
						processDuplicate(duplicates, hostEntry, key)
					}
				} else {
					// All other are duplicates
					processDuplicate(duplicates, hostEntry, key)
				}
			} else {
				cleanAfterWordsAndLines[key] = hostEntry
				processDuplicate(duplicates, hostEntry, key)
			}
		}
	}
	// Add the filtered list to nonduplicate ones.
	var combined []SimpleHTTPXEntry
	for _, entry := range cleanAfterWordsAndLines {
		combined = append(combined, entry)
	}
	for _, tld := range tlds {
		combined = AppendHTTPXEntryIfMissing(combined, tld)
	}
	return combined, duplicates

}

/*
Finds the best match for different hostnames which result in the same hash value for the response, thus having the same
content. The TLD of the project or in general is a TLD it is the preferred best duplicate match. Otherwise, the first
matching from a list of preferred ones is used. If none has matched the last one which is checked is used.
Currently it is not differentiated between ports.
Project: example.com
Duplicates: example.com (1), example.at (2), test.example.com, www.example.com (3), sub.example.com (4)
*/
func getBestDuplicateMatch(entries []SimpleHTTPXEntry, project string, tlds map[string]SimpleHTTPXEntry) SimpleHTTPXEntry {
	var match SimpleHTTPXEntry
	var currentBestMatch SimpleHTTPXEntry
	var possibleBestMatch SimpleHTTPXEntry
	var host string
	var port string
	for _, entry := range entries {
		host, port = getHostAndPort(entry.Input)
		tld := ExtractTLDFromString(host)
		// If entry is a top level domain we either use it as current best match, if it is the same as the project.
		// If not we use it as possible best match if it is an entry with port 443. If not we use it as general
		if host == tld {
			//Store each TLD for later processing, in case it gets removed, which should be the case
			match = entry
			if _, ok := tlds[host]; !ok {
				tlds[host] = entry
			}
			if tld == project {
				/* Only one can exist (but maybe several times due to ports), verify that !!! */
				//If no other best match exists, use the current TLD.
				if port == "443" {
					currentBestMatch = entry
				} else if (currentBestMatch == SimpleHTTPXEntry{}) {
					currentBestMatch = entry
				}
			} else {
				//If the entry has a lower subdomain count than the existing match, use it (sub.sub.domain.com vs. sub.domain.com)
				currentHost, currentPort := getHostAndPort(possibleBestMatch.Input)
				if (possibleBestMatch == SimpleHTTPXEntry{}) {
					possibleBestMatch = entry
				} else if subDomainCount(possibleBestMatch.Input) > subDomainCount(entry.Input) && port == "443" {
					possibleBestMatch = entry
				} else if subDomainCount(possibleBestMatch.Input) == subDomainCount(entry.Input) && port == "443" {
					if checkIfHostStringIsContained(entry.Input, wantedHosts, tld) {
						possibleBestMatch = entry
					} else {
						if hostnameLength(currentHost) >= hostnameLength(host) || currentPort != port {
							possibleBestMatch = entry
						}
					}
				} else if port == "443" {
					if currentPort != port {
						possibleBestMatch = entry
					}
				} else if currentPort != "443" {
					if checkIfHostStringIsContained(entry.Input, wantedHosts, tld) {
						match = entry
					} else if !checkIfHostStringIsContained(match.Input, wantedHosts, tld) {
						if hostnameLength(currentHost) >= hostnameLength(host) {
							match = entry
						}
					}
				}
				log.Debugf("Added non duplicate entry: %s", entry.Input)
			}
		} else if (match == SimpleHTTPXEntry{}) {
			match = entry
		} else if (match != SimpleHTTPXEntry{}) {
			//If the entry has a lower subdomain count than the existing match, use it (sub.sub.domain.com vs. sub.domain.com)
			currentHost, currentPort := getHostAndPort(match.Input)
			if tld == project {
				if subDomainCount(match.Input) >= subDomainCount(entry.Input) && port == "443" {
					if checkIfHostStringIsContained(entry.Input, wantedHosts, tld) {
						match = entry
					} else if !checkIfHostStringIsContained(match.Input, wantedHosts, tld) {
						if hostnameLength(currentHost) >= hostnameLength(host) || currentPort != port {
							match = entry
						}
					} else if port == "443" && currentPort != port {
						match = entry
					}
				} else if port == "443" && currentPort != port {
					match = entry
				} else if currentPort != "443" {
					if checkIfHostStringIsContained(entry.Input, wantedHosts, tld) {
						match = entry
					} else if !checkIfHostStringIsContained(match.Input, wantedHosts, tld) {
						if hostnameLength(currentHost) >= hostnameLength(host) {
							match = entry
						}
					}
				}
			} else {
				if subDomainCount(match.Input) > subDomainCount(entry.Input) && port == "443" {
					if checkIfHostStringIsContained(entry.Input, wantedHosts, tld) {
						match = entry
					} else if !checkIfHostStringIsContained(match.Input, wantedHosts, tld) {
						if hostnameLength(currentHost) > hostnameLength(host) || currentPort != port {
							match = entry
						}
					} else if port == "443" && currentPort != port {
						match = entry
					}
				} else if port == "443" && currentPort != port {
					match = entry
				}
			}
		}
	}

	if (currentBestMatch != SimpleHTTPXEntry{}) {
		match = currentBestMatch
	} else if (possibleBestMatch != SimpleHTTPXEntry{}) {
		match = possibleBestMatch
	}
	// Remove the match from TLDs if it exists
	host, port = getHostAndPort(match.Input)
	delete(tlds, host)

	log.Debugf("Found best match for duplicates with hash %s or words %d and lines %d is host %s", match.BodyHash, match.Words, match.Lines, match.Input)
	return match
}

func getSimpleEntriesForBodyHash(entries []SimpleHTTPXEntry, bodyHash string) []SimpleHTTPXEntry {
	var filteredEntries []SimpleHTTPXEntry
	for _, entry := range entries {
		if bodyHash == entry.BodyHash {
			filteredEntries = append(filteredEntries, entry)
		}
	}
	return filteredEntries
}

func getSimpleEntriesForMetrics(entries map[string]SimpleHTTPXEntry, match SimpleHTTPXEntry) []SimpleHTTPXEntry {
	var filteredEntries []SimpleHTTPXEntry
	for _, entry := range entries {
		var difference int
		if entry.ContentLength >= match.ContentLength {
			difference = entry.ContentLength - match.ContentLength
		} else {
			difference = match.ContentLength - entry.ContentLength
		}
		if entry.Words == match.Words && entry.Lines == match.Lines && difference > 50 {
			filteredEntries = append(filteredEntries, entry)
		}
	}
	return filteredEntries
}

func processDuplicate(duplicates map[string]Duplicate, currentEntry SimpleHTTPXEntry, currentKey string) {
	// All other are duplicates
	duplicate := duplicates[currentKey]

	if host, _ := getHostAndPort(duplicate.Hostname); host == "matomo.saubermacher.at" {
		log.Debugf("Using %s as duplicate base. Check if correct", duplicate.Hostname)
	}

	//If empty create new one
	if reflect.DeepEqual(Duplicate{}, duplicate) {
		duplicate = getDuplicate(currentEntry)
	}
	if duplicate.Hostname != currentEntry.Input {
		duplicate.DuplicateHosts = AppendIfMissing(duplicate.DuplicateHosts, currentEntry.Input)
	}
	//If a duplicate for the body hash already exists, inline it to the new duplicates entry
	if !reflect.DeepEqual(Duplicate{}, duplicates[currentEntry.BodyHash]) {
		if duplicate.Hostname != duplicates[duplicate.BodyHash].Hostname && strings.HasSuffix(duplicate.Hostname, "443") {
			//The current entry is the HTTPs one, the one from the body hash is added to the duplicate hosts list
			duplicate.DuplicateHosts = AppendIfMissing(duplicate.DuplicateHosts, duplicates[duplicate.BodyHash].Hostname)
		} else if duplicate.Hostname != duplicates[duplicate.BodyHash].Hostname && strings.HasSuffix(duplicates[duplicate.BodyHash].Hostname, "443") {
			//The entry from the body hash is the HTTPS version, thus use this one.
			duplicate.DuplicateHosts = AppendIfMissing(duplicate.DuplicateHosts, duplicate.Hostname)
			duplicate.Hostname = duplicates[duplicate.BodyHash].Hostname
		}
		duplicate.DuplicateHosts = AppendSliceIfMissingExcept(duplicate.DuplicateHosts, duplicates[currentEntry.BodyHash].DuplicateHosts, duplicate.Hostname)
		delete(duplicates, currentEntry.BodyHash)
	}
	duplicates[currentKey] = duplicate
}

func checkIfHostStringIsContained(host string, hostSlice []string, tld string) bool {
	parts := strings.Split(host, ".")
	if tld != "" {
		tldParts := strings.Split(tld, ".")
		if len(parts) > 0 && (len(parts) == len(tldParts)+1) {
			if slices.Contains(hostSlice, parts[0]) {
				return true
			}
		}
	} else {
		if len(parts) > 0 {
			if slices.Contains(hostSlice, parts[0]) {
				return true
			}
		}
	}

	return false
}

func createMapNonDuplicateForDuplicate(duplicates []Duplicate) map[string]string {
	var duplicateMap = make(map[string]string)
	for _, duplicate := range duplicates {
		for _, duplicateHost := range duplicate.DuplicateHosts {
			duplicateMap[duplicateHost] = duplicate.Hostname
		}
	}
	return duplicateMap
}
