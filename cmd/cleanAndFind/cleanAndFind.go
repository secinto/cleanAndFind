package main

import (
	"github.com/projectdiscovery/gologger"
	"github.com/secinto/cleanAndFind/processor"
)

func main() {
	// Parse the command line flags and read config files
	options := processor.ParseOptions()

	newProcessor, err := processor.NewProcessor(options)
	if err != nil {
		gologger.Fatal().Msgf("Could not create processor: %s\n", err)
	}

	err = newProcessor.CleanAndFind()
	if err != nil {
		gologger.Fatal().Msgf("Could not clean and find: %s\n", err)
	}
}
