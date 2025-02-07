package processor

import (
	"encoding/json"
	"github.com/antchfx/jsonquery"
	"gopkg.in/yaml.v3"
	"os"
	"reflect"
	"secinto/checkfix_utils"
	"strconv"
	"strings"
)

var (
	log           = checkfix_utils.NewLogger()
	appConfig     Config
	wantedHosts   = []string{"www", "mail", "portal", "webmail", "dashboard", "login", "remote", "ssh", "admin"}
	unwantedHosts = []string{"autodiscover", "sip", "lyncdiscover", "owa", "www.autodiscover", "enterpriseenrollment", "enterpriseregistration", "_domainkey", "_dmarc", "msoid"}
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
	if !strings.HasSuffix(appConfig.ProjectsPath, "/") {
		appConfig.ProjectsPath = appConfig.ProjectsPath + "/"
	}
	p.options.BaseFolder = appConfig.ProjectsPath + p.options.Project
	if !strings.HasSuffix(p.options.BaseFolder, "/") {
		p.options.BaseFolder = p.options.BaseFolder + "/"
	}
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
			ProjectsPath:     "/checkfix/projects",
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
			if p.options.OnlyClean {
				log.Infof("Creating dns_clean file from DPUx input.")
				p.CleanDNSEntries()
			} else if p.options.OnlyMail {
				var mailRecords []MailRecord
				log.Info("Obtaining all mail DNS entries for project")
				mailRecords = p.FindMailRecords()
				log.Infof("%d Mail information records have been found", len(mailRecords))
			} else {
				// Perform all functions.
				var mailRecords []MailRecord
				log.Info("Obtaining all mail DNS entries for project")
				mailRecords = p.FindMailRecords()
				log.Infof("%d Mail information records have been found", len(mailRecords))
				log.Infof("Verifying duplications of project %s", p.options.Project)
				p.CleanDomains(mailRecords, p.options.UseCleanedDNS)
				if !p.options.UseCleanedDNS {
					p.CleanDNSEntries()
				}
			}
		}
	} else {
		log.Info("No project specified. Exiting application")
	}
	return nil
}

func (p *Processor) CleanFile() {
	log.Infof("Using %s as HTTPX input file", p.options.File)
	httpxInput := GetDocumentFromFile(p.options.File)
	hostEntries := checkfix_utils.GetValuesForKey(httpxInput, "host")
	var ips []string
	if len(hostEntries) >= 1 {
		for _, hostEntry := range hostEntries {
			if value, ok := hostEntry.Value().(string); ok {
				ips = checkfix_utils.AppendIfMissing(ips, value)
			}
		}

	}
	var nonDuplicateHosts []string
	for _, ipAddress := range ips {
		cleanedHosts, _ := p.deduplicateByContent(httpxInput, ipAddress)
		for _, uniqueHost := range cleanedHosts {
			log.Debugf("Adding hostname %s to non duplicates", uniqueHost.Input)
			nonDuplicateHosts = checkfix_utils.AppendIfMissing(nonDuplicateHosts, uniqueHost.Input)
		}
	}
	checkfix_utils.WriteToFile(p.options.UniqueHostsFile, strings.Join(nonDuplicateHosts[:], "\n"))

}

func (p *Processor) CleanDNSEntries() {
	dpuxInputFile := p.options.BaseFolder + "recon/" + appConfig.DpuxFile
	log.Infof("Using DPUx input %s", dpuxInputFile)
	dpuxInput := GetDocumentFromFile(dpuxInputFile)
	var dnsEntries []DNSRecord
	for _, dpuxEntry := range dpuxInput.ChildNodes() {
		dnsEntry := CreateSimpleDNSEntryFromDPUX(dpuxEntry)
		if !reflect.DeepEqual(dnsEntry, DNSRecord{}) {
			if !strings.Contains(dnsEntry.Host, "_dmarc") && !strings.Contains(dnsEntry.Host, "_domainkey") {
				dnsEntries = AppendDNSRecordIfMissing(dnsEntries, dnsEntry)
			} else {
				log.Debugf("Not adding host %s to DNS file", dnsEntry.Host)
			}
		} else {
			log.Error("DPUx entry couldn't be parsed for and DNS entry.")
		}
	}

	log.Infof("Found %d dns records", len(dnsEntries))
	data, _ := json.MarshalIndent(dnsEntries, "", " ")
	checkfix_utils.WriteToFile(p.options.BaseFolder+"findings/dns_clean.json", string(data))

}

func (p *Processor) CleanDomains(mailRecords []MailRecord, makeCLeanedDNS bool) {
	// Get JSON file
	var httpxInput *jsonquery.Node
	httpxInputFile := p.options.BaseFolder + "recon/" + appConfig.HttpxDomainsFile
	log.Infof("Using HTTPX domains input %s", httpxInputFile)
	httpxInput = GetDocumentFromFile(httpxInputFile)
	ipsInputFile := p.options.BaseFolder + "recon/" + appConfig.DpuxIPFile
	log.Infof("Using DPUx IP input %s", ipsInputFile)
	ipsInput := checkfix_utils.ReadPlainTextFileByLines(ipsInputFile)

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
				nonDuplicateHosts = checkfix_utils.AppendIfMissing(nonDuplicateHosts, uniqueHost.Input)

				host, _ := checkfix_utils.GetHostAndPort(uniqueHost.Input)
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
				nonDuplicateHosts = checkfix_utils.AppendIfMissing(nonDuplicateHosts, dnsEntry.Host)
				dnsRecords = AppendDNSRecordIfMissing(dnsRecords, dnsEntry)
			} else {
				log.Debugf("Found DNS record with empty ipAddress during processing IP %s", ipAddress)
			}
		}
		for _, duplicateEntry := range duplicates {
			duplicateHosts = AppendDuplicatesIfMissing(duplicateHosts, duplicateEntry)
		}
	}

	for _, mailHost := range mailRecords {
		dnsEntry := GetDNSRecordForHostname(dpuxInput, mailHost.Host)
		if !reflect.DeepEqual(DNSRecord{}, dnsEntry) {
			dnsRecords = AppendDNSRecordIfMissing(dnsRecords, dnsEntry)
			nonDuplicateHosts = checkfix_utils.AppendIfMissing(nonDuplicateHosts, dnsEntry.Host)
			for _, duplicate := range duplicateHosts {
				if duplicate.Hostname == dnsEntry.Host {
					continue
				}
				duplicate.DuplicateHosts = checkfix_utils.RemoveFromStringArray(duplicate.DuplicateHosts, dnsEntry.Host)
			}
		}
	}

	var cleanedDomains []string
	var cleanedDomainsWithPorts []string

	duplicateToNonDuplicateMap := createMapNonDuplicateForDuplicate(duplicateHosts)

	for _, hostEntry := range nonDuplicateHosts {
		host, port := checkfix_utils.GetHostAndPort(hostEntry)

		if !checkIfHostStringIsContained(host, unwantedHosts, "") {
			cleanedDomains = checkfix_utils.AppendIfMissing(cleanedDomains, host)
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
			log.Infof("Not using IP %s", host)
		}
	}
	log.Infof("Found %d non duplicate hosts without port", len(cleanedDomains))
	cleanedDomainsString := checkfix_utils.ConvertStringArrayToString(cleanedDomains, "\n")

	checkfix_utils.WriteToFile(p.options.BaseFolder+"domains_clean.txt", cleanedDomainsString)

	log.Infof("Found %d non duplicate hosts with port", len(cleanedDomainsWithPorts))
	cleanedDomainsWithPortsString := checkfix_utils.ConvertStringArrayToString(cleanedDomainsWithPorts, "\n")
	checkfix_utils.WriteToTextFileInProject(p.options.BaseFolder+"domains_clean_with_http_ports.txt", cleanedDomainsWithPortsString)

	log.Infof("Found %d duplicate host entries", len(duplicateHosts))
	data, _ := json.MarshalIndent(duplicateHosts, "", " ")
	checkfix_utils.WriteToTextFileInProject(p.options.BaseFolder+"findings/duplicates.json", string(data))

	if makeCLeanedDNS {
		log.Infof("Found %d dns records", len(dnsRecords))
		data, _ = json.MarshalIndent(dnsRecords, "", " ")
		checkfix_utils.WriteToTextFileInProject(p.options.BaseFolder+"findings/dns_clean.json", string(data))
	}
	log.Info("Created cleaned domains file for project")
}

func (p *Processor) FindMailRecords() []MailRecord {
	var mailRecord MailRecord

	mailRecords := make(map[string]MailRecord)

	dpuxFile := p.options.BaseFolder + "recon/" + appConfig.DpuxFile
	log.Infof("Using DPUX DNS input %s", dpuxFile)
	input := GetDocumentFromFile(dpuxFile)

	// Check all host entries from DPUx, reflects all existing and resolved host names (at least for MX, TXT, A, AAAA, and CNAME).
	allHostRecords := checkfix_utils.GetAllJSONNodesForKey(input, "host")
	for _, hostRecordNode := range allHostRecords {
		entry := GetDPUXEntry(hostRecordNode)

		if strings.HasPrefix(entry.Host, "_dmarc.") || strings.Contains(entry.Host, "._domainkey.") {
			continue
		}

		log.Infof("Processing host entry %s", entry.Host)
		if _, ok := mailRecords[entry.Host]; !ok {
			mailRecord = MailRecord{
				Host: entry.Host,
			}
		} else {
			mailRecord = mailRecords[entry.Host]
		}

		if len(entry.MX) > 0 {
			mailRecord.MXRecords = checkfix_utils.AppendIfMissingAll(mailRecord.MXRecords, entry.MX...)
		}
		// Check if the host has an SPF entry.
		isSPFRow := false
		lastSPFRow := false

		if len(entry.TXT) > 0 {
			for _, txtEntry := range entry.TXT {
				if strings.Contains(strings.ToLower(txtEntry), "spf") && !lastSPFRow {
					mailRecord.SPFEntry = mailRecord.SPFEntry + removeWhitespaces(txtEntry)
					isSPFRow = true
				}
				if isSPFRow && strings.HasSuffix(strings.ToLower(txtEntry), "all") {
					lastSPFRow = true
				}
				if strings.Contains(strings.ToLower(txtEntry), "dkim") {
					mailRecord.Infos = append(mailRecord.Infos, "DKIM entry illegally placed")
				}
				if strings.Contains(strings.ToLower(txtEntry), "dmarc") {
					mailRecord.Infos = append(mailRecord.Infos, "DMARC entry illegally placed")
				}
			}
		}
		tld, _ := ExtractTLDAndSubdomainFromString(entry.Host)

		log.Debugf("Checking DMARC entry for host %s", entry.Host)
		p.getDMARCEntryForHost(entry.Host, &mailRecord, input)

		log.Debugf("Checking DKIM entry for host %s", entry.Host)
		p.getDKIMEntryForHost(entry.Host, &mailRecord, input)

		if tld != entry.Host && len(mailRecord.DMARCEntry) == 0 && (len(mailRecord.MXRecords) != 0 || len(mailRecord.DKIMEntries) != 0 || len(mailRecord.SPFEntry) != 0) {
			log.Debugf("Checking if a TLD %s DMARC entry exists for host %s", tld, entry.Host)
			p.getDMARCEntryForHost(tld, &mailRecord, input)
			mailRecord.Infos = append(mailRecord.Infos, "DMARC entries are taken from the top level domain")

		}

		if !strings.HasPrefix(entry.Host, "_dmarc.") && !strings.Contains(entry.Host, "_domainkey.") && (len(mailRecord.MXRecords) != 0 || len(mailRecord.SPFEntry) != 0 || len(mailRecord.DKIMEntries) != 0) {
			mailRecords[entry.Host] = mailRecord
			log.Infof("Added DNS record for host %s", entry.Host)
		} else if tld == entry.Host && len(entry.Host) > 0 {
			mailRecords[entry.Host] = mailRecord
			log.Infof("Added DNS record for host %s", entry.Host)
		} else {
			log.Debugf("No mail relevant DNS record for host %s", entry.Host)
		}
	}

	var mxRecords []MailRecord
	for _, record := range mailRecords {
		mxRecords = append(mxRecords, record)
	}

	data, _ := json.MarshalIndent(mxRecords, "", " ")
	checkfix_utils.CreateDirectoryIfNotExists(p.options.BaseFolder + "findings/")
	checkfix_utils.WriteToFile(p.options.BaseFolder+"findings/mailsecurity.json", string(data))

	return mxRecords
}

//-------------------------------------------
//			Helper methods
//-------------------------------------------

func (p *Processor) getDMARCEntryForHost(host string, record *MailRecord, input *jsonquery.Node) {
	dmarcEntries := checkfix_utils.GetNodesFromSpecificQueryViaEquals(input, "host", "_dmarc."+host)
	for _, entry := range dmarcEntries {
		txtDMARCEntry := checkfix_utils.GetValuesFromNode(entry, "txt")
		for _, txtEntry := range txtDMARCEntry {
			if txtEntry != "" {
				if strings.Contains(txtEntry, "DMARC") {
					log.Infof("Adding dmarc entry for host %s", host)
					record.DMARCEntry = checkfix_utils.AppendIfMissing(record.DMARCEntry, removeWhitespaces(txtEntry))
				} else {
					record.Infos = append(record.Infos, "DKIM entry illegally placed")

					log.Infof("TXT record for %s contains invalid content: %s", "_dmarc."+host, txtEntry)
				}
			}
		}
	}
}

func (p *Processor) getDKIMEntryForHost(host string, record *MailRecord, input *jsonquery.Node) {
	dkimEntries := checkfix_utils.GetAllEntriesByContains(input, "host", []string{"_domainkey." + host})
	if len(dkimEntries) > 0 {
		var entries []DKIM
		for _, dkimEntry := range dkimEntries {
			if hostName, ok := dkimEntry.Value().(string); ok {
				if !strings.HasPrefix(hostName, "thisshouldnot.work.") {
					entry := DKIM{Selector: hostName}

					txtValue := checkfix_utils.GetValuesFromNode(dkimEntry.Parent, "txt")

					if len(txtValue) > 0 {
						entry.TXT = removeWhitespaces(strings.Join(txtValue, ""))
					}
					cnameValue := checkfix_utils.GetValuesFromNode(dkimEntry.Parent, "cname")
					if len(cnameValue) > 0 {
						entry.CNAME = removeWhitespaces(strings.Join(cnameValue, ""))
					}
					if len(entry.CNAME) > 0 || len(entry.TXT) > 0 {
						log.Infof("Adding DKIM entry for host %s", hostName)
						entries = append(entries, entry)
					}
				} else {
					log.Infof("Found wildcard DNS entry for DKIM. Not using entry for host %s", hostName)
				}
			} else {
				log.Errorf("Found DKIM entry which couldn't be resolved to a host name. %s", dkimEntry)
			}
		}
		if len(entries) > 0 {
			record.DKIMEntries = entries
		}
	}
}

func (p *Processor) getDMARCEntryForDPUXEntry(host string, record *MailRecord, dpuxEntry DPUXEntry) {
	txtDMARCEntry := dpuxEntry.TXT
	for _, txtEntry := range txtDMARCEntry {
		if txtEntry != "" {
			if strings.Contains(txtEntry, "DMARC") {
				log.Infof("Adding dmarc entry for host %s", host)
				record.DMARCEntry = checkfix_utils.AppendIfMissing(record.DMARCEntry, removeWhitespaces(txtEntry))
			} else {
				record.Infos = append(record.Infos, "DKIM entry illegally placed")

				log.Infof("TXT record for %s contains invalid content: %s", "_dmarc."+host, txtEntry)
			}
		}
	}
}

func (p *Processor) deduplicateByContent(httpxInput *jsonquery.Node, ipaddress string) ([]SimpleHTTPXEntry, map[string]Duplicate) {
	hostsOnSameIP := GetHTTPXEntryForIPAddress(httpxInput, ipaddress)
	cleanAfterHash := make(map[string]SimpleHTTPXEntry)
	// TLDs are always used, even if they are duplicates
	tlds := make(map[string]SimpleHTTPXEntry)
	duplicates := make(map[string]Duplicate)
	cleanAfterWordsAndLines := make(map[string]SimpleHTTPXEntry)
	for _, hostEntry := range hostsOnSameIP {
		log.Debugf("Checking hostname %s on %s", hostEntry.Input, ipaddress)
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
					log.Errorf("No best match found for hash")
					cleanAfterHash[hostEntry.BodyHash] = hostEntry
				}
				processDuplicate(duplicates, cleanAfterHash[hostEntry.BodyHash], hostEntry.BodyHash)

			} else {
				//Only one exists, use it
				cleanAfterHash[hostEntry.BodyHash] = hostEntry
				processDuplicate(duplicates, cleanAfterHash[hostEntry.BodyHash], hostEntry.BodyHash)
			}
		} else {
			processDuplicate(duplicates, cleanAfterWordsAndLines[hostEntry.BodyHash], hostEntry.BodyHash)
		}
	}
	// Also find duplicates based on the words and lines from the HTTP response. If they are the same
	// for the same IP it is very likely that the content is the same although some minor thing changed
	// and therefore the hash changed. (Used IP, hostname or some other changes such as generated Javascript)
	// See austria-beteiligungen (hvw-wegraz.at), jaw.or.at for reasons.
	for _, hostEntry := range cleanAfterHash {
		//Process each entry from cleanAfterHash array
		//Generate the key for the current entry
		key := strconv.Itoa(hostEntry.Words) + "-" + strconv.Itoa(hostEntry.Lines) + "-" + hostEntry.Title
		if len(cleanAfterHash) > 1 {
			log.Debugf("Checking hostname %s", hostEntry.Input)
			if _, ok := cleanAfterWordsAndLines[key]; !ok {
				possibleDupes := getDuplicatesWithSlightDifference(cleanAfterHash, hostEntry, p.options.Project)
				if len(possibleDupes) > 1 {
					bestMatch := getBestDuplicateMatch(possibleDupes, p.options.Project, tlds)
					if (bestMatch != SimpleHTTPXEntry{}) {
						// Use the best match
						cleanAfterWordsAndLines[key] = bestMatch
					} else {
						// If empty, meaning no best match found, use the current one.
						log.Errorf("No best match found for words and lines")
						cleanAfterWordsAndLines[key] = hostEntry
					}
					processDuplicate(duplicates, cleanAfterWordsAndLines[key], key)
					if cleanAfterWordsAndLines[key].Input != hostEntry.Input {
						processDuplicate(duplicates, hostEntry, key)
					}
				} else {
					//Only one entry exists, no duplicates, use it.
					if _, ok := cleanAfterWordsAndLines[key]; !ok {
						cleanAfterWordsAndLines[key] = hostEntry
					} else {
						key = hostEntry.BodyHash
						cleanAfterWordsAndLines[key] = hostEntry
					}
					processDuplicate(duplicates, hostEntry, key)
				}
			} else {
				// All other are duplicates
				if isHostExcludedFromDuplicateCheck(hostEntry.Input, p.options.Project) {
					log.Debugf("Host %s is excluded from duplicate check!", hostEntry.Input)
					key = hostEntry.BodyHash
					cleanAfterWordsAndLines[key] = hostEntry
				}
				processDuplicate(duplicates, hostEntry, key)
			}
		} else {
			if _, ok := cleanAfterWordsAndLines[key]; !ok {
				cleanAfterWordsAndLines[key] = hostEntry
			} else {
				key = hostEntry.BodyHash
				cleanAfterWordsAndLines[key] = hostEntry
			}
			processDuplicate(duplicates, hostEntry, key)
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
		host, port = checkfix_utils.GetHostAndPort(entry.Input)
		tld := checkfix_utils.ExtractTLDFromString(host)
		// If entry is a top level domain we either use it as current best match, if it is the same as the project.
		// If not we use it as possible best match if it is an entry with port 443. If not we use it as general
		if host == tld {
			//Store each TLD for later processing, in case it gets removed, which should be the case
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
				if (possibleBestMatch == SimpleHTTPXEntry{}) {
					possibleBestMatch = entry
				} else {
					_, currentPort := checkfix_utils.GetHostAndPort(possibleBestMatch.Input)
					if port == "443" {
						possibleBestMatch = getInnerBestMatch(project, possibleBestMatch, entry)
					} else if currentPort != "443" {
						possibleBestMatch = getInnerBestMatch(project, possibleBestMatch, entry)
					}
				}
			}
		} else {
			/* If none exists use it */
			if (match == SimpleHTTPXEntry{}) {
				match = entry
			} else {
				//Check if it should be used either if the port is 443 or the port of the currently and
				//the port to check are not 443. Otherwise stay with as it is.
				_, currentPort := checkfix_utils.GetHostAndPort(match.Input)
				if port == "443" {
					match = getInnerBestMatch(project, match, entry)
				} else if currentPort != "443" {
					match = getInnerBestMatch(project, match, entry)
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
	host, port = checkfix_utils.GetHostAndPort(match.Input)
	delete(tlds, host)

	log.Debugf("Found best match for duplicates with hash %s or words %d and lines %d is host %s", match.BodyHash, match.Words, match.Lines, match.Input)
	return match
}

func getInnerBestMatch(project string, currentMatch SimpleHTTPXEntry, entryToCheck SimpleHTTPXEntry) SimpleHTTPXEntry {
	var match SimpleHTTPXEntry
	currentHost, _ := checkfix_utils.GetHostAndPort(currentMatch.Input)
	host, _ := checkfix_utils.GetHostAndPort(entryToCheck.Input)
	tldCurrent := checkfix_utils.ExtractTLDFromString(currentHost)
	tldEntry := checkfix_utils.ExtractTLDFromString(host)
	if tldEntry == project || tldCurrent != project {
		if checkfix_utils.GetSubDomainCount(currentHost) >= checkfix_utils.GetSubDomainCount(host) {
			if checkIfHostStringIsContained(host, wantedHosts, tldEntry) {
				match = entryToCheck
			} else if !checkIfHostStringIsContained(currentHost, wantedHosts, tldCurrent) {
				if checkfix_utils.GetHostnameLength(currentHost) >= checkfix_utils.GetHostnameLength(host) {
					match = entryToCheck
				}
			}
		}
	} else {
		if checkfix_utils.GetSubDomainCount(currentHost) > checkfix_utils.GetSubDomainCount(host) {
			if checkIfHostStringIsContained(host, wantedHosts, tldEntry) {
				match = entryToCheck
			} else if !checkIfHostStringIsContained(currentHost, wantedHosts, tldCurrent) {
				if checkfix_utils.GetHostnameLength(currentHost) > checkfix_utils.GetHostnameLength(host) {
					match = entryToCheck
				}
			}
		}
	}
	if !(match == SimpleHTTPXEntry{}) {
		return match
	} else {
		return currentMatch
	}
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

func getDuplicatesWithSlightDifference(entries map[string]SimpleHTTPXEntry, match SimpleHTTPXEntry, project string) []SimpleHTTPXEntry {
	var filteredEntries []SimpleHTTPXEntry
	if isHostExcludedFromDuplicateCheck(match.Input, project) {
		log.Debugf("Host %s is excluded from duplicate check!", match.Input)
	} else {
		for _, entry := range entries {
			var difference int
			if entry.ContentLength >= match.ContentLength {
				difference = entry.ContentLength - match.ContentLength
			} else {
				difference = match.ContentLength - entry.ContentLength
			}
			if entry.Words == match.Words && entry.Lines == match.Lines {
				if difference > 50 {
					log.Infof("Uses possible duplicate %s despite difference in length of %d", entry.Input, difference)
				}
				if entry.Title == match.Title && !isHostExcludedFromDuplicateCheck(entry.Input, project) {
					filteredEntries = append(filteredEntries, entry)
				}
			}
		}
	}
	return filteredEntries
}

func processDuplicate(duplicates map[string]Duplicate, currentEntry SimpleHTTPXEntry, currentKey string) {
	// All other are duplicates
	duplicate := duplicates[currentKey]

	if host, _ := checkfix_utils.GetHostAndPort(duplicate.Hostname); host == "matomo.saubermacher.at" {
		log.Debugf("Using %s as duplicate base. Check if correct", duplicate.Hostname)
	}

	//If empty create new one
	if reflect.DeepEqual(Duplicate{}, duplicate) {
		duplicate = getDuplicate(currentEntry)
	} else if duplicate.Hostname != currentEntry.Input {
		duplicate.DuplicateHosts = checkfix_utils.AppendIfMissing(duplicate.DuplicateHosts, currentEntry.Input)
	}
	//If a duplicate for the body hash already exists, inline it to the new duplicates entry
	if !reflect.DeepEqual(Duplicate{}, duplicates[currentEntry.BodyHash]) {
		duplicate.DuplicateHosts = checkfix_utils.AppendSliceIfMissingExcept(duplicate.DuplicateHosts, duplicates[currentEntry.BodyHash].DuplicateHosts, duplicate.Hostname)
		delete(duplicates, currentEntry.BodyHash)
	}
	duplicates[currentKey] = duplicate
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
