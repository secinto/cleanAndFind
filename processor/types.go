package processor

const VERSION = "0.3.0"

type Config struct {
	ProjectsPath     string `yaml:"projects_path,omitempty"`
	HttpxDomainsFile string `yaml:"httpx_domains,omitempty"`
	DpuxFile         string `yaml:"dpux,omitempty"`
	DpuxIPFile       string `yaml:"dpux_ip,omitempty"`
}

type Options struct {
	SettingsFile    string
	Project         string
	File            string
	BaseFolder      string
	UniqueHostsFile string
	OnlyClean       bool
	OnlyMail        bool
	OnlyDedup       bool
	UseCleanedDNS   bool
	Silent          bool
	Version         bool
	NoColor         bool
	Verbose         bool
	Debug           bool
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
	DMARCEntry  []string `json:"DMARCEntry,omitempty"`
	DKIMEntries []DKIM   `json:"DKIMEntries,omitempty"`
	Infos       []string `json:"Infos,omitempty"`
}

type DKIM struct {
	Selector string
	TXT      string
	CNAME    string
}

type DPUXEntry struct {
	Host       string   `json:"host"`
	TXT        []string `json:"txt"`
	CNAME      []string `json:"cname"`
	MX         []string `json:"mx"`
	A          []string `json:"a"`
	AAAA       []string `json:"aaaa"`
	Resolver   []string `json:"resolver"`
	SOA        []SOA    `json:"soa"`
	TTL        int      `json:"ttl"`
	StatusCode string   `json:"status_code"`
	Timestamp  string   `json:"timestamp"`
}

type SOA struct {
	Name    string `json:"name"`
	Ns      string `json:"ns"`
	Mailbox string `json:"mailbox"`
	Serial  int    `json:"serial"`
	Refresh int    `json:"refresh"`
	Retry   int    `json:"retry"`
	Expire  int    `json:"expire"`
	Minttl  int    `json:"minttl"`
}

type DNSRecord struct {
	Host          string   `json:"Host"`
	CNAME         []string `json:"CNAMES,omitempty"`
	IPv4Addresses []string `json:"IPv4Addresses,omitempty"`
	IPv6Addresses []string `json:"IPv6Addresses,omitempty"`
	WhoisInfo     string   `json:"WhoisInfo,omitempty"`
}

type Duplicate struct {
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

func getDuplicate(entry SimpleHTTPXEntry) Duplicate {
	duplicate := Duplicate{
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
