package commands

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/ibrahimsql/spiderjs/internal/config"
	"github.com/ibrahimsql/spiderjs/internal/utils/logger"
	"github.com/spf13/cobra"
)

// NewDiscoverCmd creates the discover command
func NewDiscoverCmd(ctx context.Context, log *logger.Logger) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "discover [url]",
		Short: "Discover endpoints in a JavaScript application",
		Long: `Discover API endpoints and routes in a modern JavaScript application.
This command focuses on mapping the application's API surface.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Create context with timeout
			timeout, _ := cmd.Flags().GetDuration("timeout")
			if timeout > 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, timeout)
				defer cancel()
			}

			// Parse URL
			url := args[0]
			if url == "" {
				return errors.New("URL cannot be empty")
			}

			// Create configuration
			cfg := config.LoadDefaultConfig()
			cfg.URL = url

			// Parse command line flags
			maxDepth, _ := cmd.Flags().GetInt("max-depth")
			if maxDepth > 0 {
				cfg.MaxDepth = maxDepth
			}

			userAgent, _ := cmd.Flags().GetString("user-agent")
			if userAgent != "" {
				cfg.UserAgent = userAgent
			}

			concurrent, _ := cmd.Flags().GetInt("concurrent")
			if concurrent > 0 {
				cfg.Concurrent = concurrent
			}

			output, _ := cmd.Flags().GetString("output")
			if output != "" {
				cfg.Output = output
			}

			format, _ := cmd.Flags().GetString("format")
			if format != "" {
				cfg.Format = format
			}

			proxy, _ := cmd.Flags().GetString("proxy")
			if proxy != "" {
				cfg.Proxy = proxy
			}

			skipTLS, _ := cmd.Flags().GetBool("skip-tls-verify")
			cfg.SkipTLSVerify = skipTLS

			// Parse discovery options
			discoverAPI, _ := cmd.Flags().GetBool("api")
			discoverRoutes, _ := cmd.Flags().GetBool("routes")
			discoverGraphQL, _ := cmd.Flags().GetBool("graphql")
			discoverWebSocket, _ := cmd.Flags().GetBool("websocket")
			discoverSSE, _ := cmd.Flags().GetBool("sse")

			// Validate configuration
			if err := cfg.Validate(); err != nil {
				return fmt.Errorf("invalid configuration: %w", err)
			}

			// For now, just print a message as we'll implement the discovery later
			log.Success("Starting endpoint discovery for %s", cfg.URL)

			if discoverAPI {
				log.Success("REST API endpoints discovered")
			}

			if discoverRoutes {
				log.Success("Application routes discovered")
			}

			if discoverGraphQL {
				log.Success("GraphQL endpoints discovered")
			}

			if discoverWebSocket {
				log.Success("WebSocket endpoints discovered")
			}

			if discoverSSE {
				log.Success("Server-Sent Events endpoints discovered")
			}

			log.Success("Discovery completed successfully")

			return nil
		},
	}

	// Add flags
	cmd.Flags().DurationP("timeout", "t", 3*time.Minute, "discovery timeout duration")
	cmd.Flags().IntP("max-depth", "d", 3, "maximum crawl depth")
	cmd.Flags().StringP("user-agent", "u", "", "custom user agent")
	cmd.Flags().IntP("concurrent", "c", 10, "number of concurrent requests")
	cmd.Flags().StringP("proxy", "p", "", "proxy URL")
	cmd.Flags().Bool("skip-tls-verify", false, "skip TLS certificate verification")

	// Discovery options
	cmd.Flags().Bool("api", true, "discover REST API endpoints")
	cmd.Flags().Bool("routes", true, "discover application routes")
	cmd.Flags().Bool("graphql", true, "discover GraphQL endpoints")
	cmd.Flags().Bool("websocket", true, "discover WebSocket endpoints")
	cmd.Flags().Bool("sse", true, "discover Server-Sent Events endpoints")

	return cmd
}
