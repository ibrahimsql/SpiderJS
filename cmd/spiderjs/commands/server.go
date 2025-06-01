package commands

import (
	"context"
	"fmt"
	"os"

	"github.com/ibrahimsql/spiderjs/internal/config"
	"github.com/ibrahimsql/spiderjs/internal/server"
	"github.com/ibrahimsql/spiderjs/internal/utils/logger"
	"github.com/spf13/cobra"
)

// NewServerCmd creates the server command
func NewServerCmd(ctx context.Context, log *logger.Logger) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "server",
		Short: "Start the SpiderJS web server",
		Long: `Start a web server that provides a user interface for SpiderJS.
This allows you to scan and analyze JavaScript applications through a web interface.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Parse command line flags
			host, _ := cmd.Flags().GetString("host")
			port, _ := cmd.Flags().GetInt("port")

			// Load configuration
			cfg := config.LoadDefaultConfig()

			// Create server
			srv, err := server.NewServer(cfg, log)
			if err != nil {
				return fmt.Errorf("failed to create server: %w", err)
			}

			// Start server
			log.Success("Starting SpiderJS web server on %s:%d", host, port)

			// Start server in a goroutine
			go func() {
				if err := srv.Start(ctx, host, port); err != nil {
					log.ErrorMsg("Server error: %v", err)
					os.Exit(1)
				}
			}()

			log.Success("Server started successfully. Press Ctrl+C to stop.")

			// Wait for context cancellation
			<-ctx.Done()

			// Server will be shut down by the Start method when context is cancelled
			log.Success("Server stopped gracefully")
			return nil
		},
	}

	// Add flags
	cmd.Flags().String("host", "127.0.0.1", "server host address")
	cmd.Flags().IntP("port", "p", 8080, "server port")
	cmd.Flags().Bool("tls", false, "enable TLS")
	cmd.Flags().String("cert", "", "TLS certificate file")
	cmd.Flags().String("key", "", "TLS key file")

	return cmd
}
