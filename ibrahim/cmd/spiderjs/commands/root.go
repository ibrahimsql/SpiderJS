package commands

import (
	"fmt"
	"os"

	"github.com/ibrahimsql/spiderjs/internal/utils/logger"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// NewRootCommand creates the root command
func NewRootCommand(log *logger.Logger) *cobra.Command {
	// Root command
	rootCmd := &cobra.Command{
		Use:   "spiderjs",
		Short: "SpiderJS - JavaScript Security Analyzer",
		Long: `SpiderJS is a security tool for analyzing JavaScript web applications.
It detects vulnerabilities, insecure dependencies, and security misconfigurations.

For detailed documentation, visit: https://github.com/ibrahimsql/spiderjs`,
		SilenceUsage:  true,
		SilenceErrors: true,
		Version:       "0.1.0", // This will be replaced during build
	}

	// Persistent flags for all commands
	rootCmd.PersistentFlags().Bool("debug", false, "enable debug logging")
	rootCmd.PersistentFlags().Bool("quiet", false, "suppress all output except errors")
	rootCmd.PersistentFlags().String("log-format", "console", "log format (console, json)")
	rootCmd.PersistentFlags().String("log-level", "info", "log level (debug, info, warn, error)")
	rootCmd.PersistentFlags().String("config", "", "config file (default is $HOME/.spiderjs.yaml)")

	// Bind flags to viper
	viper.BindPFlag("debug", rootCmd.PersistentFlags().Lookup("debug"))
	viper.BindPFlag("quiet", rootCmd.PersistentFlags().Lookup("quiet"))
	viper.BindPFlag("log.format", rootCmd.PersistentFlags().Lookup("log-format"))
	viper.BindPFlag("log.level", rootCmd.PersistentFlags().Lookup("log-level"))

	// Initialize config
	cobra.OnInitialize(func() {
		// If a config file is provided, read it
		if configFile := rootCmd.PersistentFlags().Lookup("config").Value.String(); configFile != "" {
			viper.SetConfigFile(configFile)
		} else {
			// Search for config in home directory with name ".spiderjs" (without extension)
			viper.AddConfigPath(os.Getenv("HOME"))
			viper.AddConfigPath(".")
			viper.SetConfigName(".spiderjs")
		}

		// Read config
		if err := viper.ReadInConfig(); err == nil {
			if debug, _ := rootCmd.PersistentFlags().GetBool("debug"); debug {
				fmt.Println("Using config file:", viper.ConfigFileUsed())
			}
		}

		// Set log level from flags
		logLevel := rootCmd.PersistentFlags().Lookup("log-level").Value.String()
		debug, _ := rootCmd.PersistentFlags().GetBool("debug")
		quiet, _ := rootCmd.PersistentFlags().GetBool("quiet")

		if debug {
			log.SetVerbose()
		} else if quiet {
			log.SetQuiet()
		} else {
			log.SetLevel(logLevel)
		}

		// Set log format
		logFormat := rootCmd.PersistentFlags().Lookup("log-format").Value.String()
		log.SetFormat(logFormat)
	})

	// Add commands
	rootCmd.AddCommand(
		NewScanCommand(log),
		NewAnalyzeCommand(log),
		NewVersionCommand(log),
	)

	return rootCmd
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	log := logger.NewLogger()
	rootCmd := NewRootCommand(log)

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		os.Exit(1)
	}
}
