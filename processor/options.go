package processor

import (
	"fmt"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/goflags"
	folderutil "github.com/projectdiscovery/utils/folder"
	"github.com/sirupsen/logrus"
	"os"
	"path/filepath"
)

var (
	defaultSettingsLocation = filepath.Join(folderutil.HomeDirOrDefault("."), ".config/cleanAndFind/settings.yaml")
)

type Options struct {
	SettingsFile    string
	Project         string
	File            string
	BaseFolder      string
	UniqueHostsFile string
	OnlyClean       bool
	OnlyDedup       bool
	UseCleanedDNS   bool
	Silent          bool
	Version         bool
	NoColor         bool
	Verbose         bool
	Debug           bool
}

// ParseOptions parses the command line flags provided by a user
func ParseOptions() *Options {
	options := &Options{}
	var err error
	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription(fmt.Sprintf("cleanAndFind %s - Remove duplicate entries from subdomain enumeration amd find security settings", VERSION))

	flagSet.CreateGroup("input", "Input",
		flagSet.StringVarP(&options.Project, "project", "p", "", "project name for metadata addition"),
		flagSet.StringVarP(&options.File, "file", "f", "", "use a specific input file instead of the default one (http_from.domains.output.json). If specified only deduplication is performed."),
	)

	flagSet.CreateGroup("output", "Output",
		flagSet.StringVarP(&options.UniqueHostsFile, "uniqueHostsFile", "uhf", "uniqueHosts.txt", "file name to which the unique hosts should be written, only valid if a specific input file has been specified"),
	)

	flagSet.CreateGroup("config", "Config",
		flagSet.StringVarP(&options.SettingsFile, "config", "c", defaultSettingsLocation, "settings (Yaml) file location"),
		flagSet.BoolVarP(&options.OnlyDedup, "onlyDedup", "od", false, "only perform deduplication (no cleaning)"),
		flagSet.BoolVarP(&options.OnlyClean, "onlyClean", "oc", false, "only perform DNS file creation (no deduplication)"),
		flagSet.BoolVarP(&options.UseCleanedDNS, "useCleanedDNS", "ucd", false, "use the cleaned and deduplicated host information to create DNS file (dns_clean.json)"),
	)

	flagSet.CreateGroup("debug", "Debug",
		flagSet.BoolVar(&options.Silent, "silent", false, "show only results in output"),
		flagSet.BoolVar(&options.Version, "version", false, "show version of the project"),
		flagSet.BoolVar(&options.Debug, "d", false, "show Debug output"),
		flagSet.BoolVar(&options.Verbose, "v", false, "show verbose output"),
		flagSet.BoolVarP(&options.NoColor, "no-color", "nc", false, "disable colors in output"),
	)

	if err := flagSet.Parse(); err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}

	options.configureOutput()

	if options.Version {
		fmt.Printf("Current Version: %s\n", VERSION)
		os.Exit(0)
	}

	// Validate the options passed by the user and if any
	// invalid options have been used, exit.
	err = options.validateOptions()
	if err != nil {
		log.Fatalf("Program exiting: %v\n", err)
	}

	return options
}

func (options *Options) configureOutput() {
	if options.Debug {
		log.SetLevel(logrus.DebugLevel)
	}
	if options.Verbose {
		log.SetLevel(logrus.TraceLevel)
	}

	if options.NoColor {
		log.SetFormatter(&logrus.TextFormatter{
			PadLevelText:     true,
			ForceColors:      false,
			DisableTimestamp: true,
		})
	}

	if options.Silent {
		log.SetLevel(logrus.PanicLevel)
	}
}

// validateOptions validates the configuration options passed
func (options *Options) validateOptions() error {

	// Both verbose and silent flags were used
	if options.Verbose && options.Silent {
		return errors.New("both verbose and silent mode specified")
	}
	if options.File != "" {
		options.OnlyDedup = true
	}

	return nil
}
