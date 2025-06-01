package commands

import (
	"encoding/json"
	"fmt"

	"github.com/ibrahimsql/spiderjs/internal/utils/logger"
	"github.com/ibrahimsql/spiderjs/pkg/version"
	"github.com/spf13/cobra"
)

// NewVersionCommand creates the version command
func NewVersionCommand(log *logger.Logger) *cobra.Command {
	var verbose bool
	var jsonOutput bool

	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "Print the version information",
		Long:  "Print the version, build information, and platform details of SpiderJS",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			// Get version info
			info := version.GetInfo()

			if jsonOutput {
				// Output as JSON
				data, err := json.MarshalIndent(info, "", "  ")
				if err != nil {
					log.Error("Failed to marshal version info", "error", err)
					return
				}
				fmt.Println(string(data))
				return
			}

			if verbose {
				// Print detailed version info
				log.Info("SpiderJS Version Information")
				log.Info("----------------------------")
				log.Info(fmt.Sprintf("Version:      %s", info.Version))
				log.Info(fmt.Sprintf("Git Commit:   %s", info.GitCommit))
				log.Info(fmt.Sprintf("Build Date:   %s", info.BuildDate))
				log.Info(fmt.Sprintf("Go Version:   %s", info.GoVersion))
				log.Info(fmt.Sprintf("Platform:     %s", info.Platform))
			} else {
				// Print simple version info
				fmt.Printf("SpiderJS v%s\n", info.Version)
			}
		},
	}

	versionCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "print detailed version information")
	versionCmd.Flags().BoolVar(&jsonOutput, "json", false, "output in JSON format")

	return versionCmd
}
