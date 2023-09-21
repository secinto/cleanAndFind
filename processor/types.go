package processor

const VERSION = "0.2.4"

type Config struct {
	S2SPath          string `yaml:"s2s_path,omitempty"`
	HttpxDomainsFile string `yaml:"httpx_domains,omitempty"`
	DpuxFile         string `yaml:"dpux,omitempty"`
	DpuxIPFile       string `yaml:"dpux_ip,omitempty"`
}

type Processor struct {
	options *Options
}

type SimpleHTTPXEntry struct {
	Host          string
	BodyHash      string
	Status        int
	ContentLength int
	Lines         int
	Words         int
	Input         string
	URL           string
	Title         string
}

type MailRecord struct {
	Host        string   `json:"Host"`
	MXRecords   []string `json:"MXRecords"`
	SPFEntry    string   `json:"SPFEntry,omitempty"`
	DMARCEntry  string   `json:"DMARCEntry,omitempty"`
	DKIMEntries []string `json:"DKIMEntries,omitempty"`
}

type DNSRecord struct {
	Host          string   `json:"Host"`
	CNAME         []string `json:"CNAMES,omitempty"`
	IPv4Addresses []string `json:"IPv4Addresses,omitempty"`
	IPv6Addresses []string `json:"IPv6Addresses,omitempty"`
	WhoisInfo     string   `json:"WhoisInfo,omitempty"`
}

type Duplicates struct {
	Hostname       string   `json:"hostname,omitempty"`
	IP             string   `json:"ip,omitempty"`
	URL            string   `json:"url,omitempty"`
	BodyHash       string   `json:"bodyHash,omitempty"`
	ContentLength  int      `json:"contentLength,omitempty"`
	Lines          int      `json:"lines,omitempty"`
	Words          int      `json:"words,omitempty"`
	Status         int      `json:"status,omitempty"`
	DuplicateHosts []string `json:"duplicateHosts,omitempty"`
}

func getDuplicate(entry SimpleHTTPXEntry) Duplicates {
	duplicate := Duplicates{
		Hostname:       entry.Input,
		IP:             entry.Host,
		BodyHash:       entry.BodyHash,
		ContentLength:  entry.ContentLength,
		Lines:          entry.Lines,
		Words:          entry.Words,
		URL:            entry.URL,
		Status:         entry.Status,
		DuplicateHosts: []string{},
	}
	return duplicate
}
