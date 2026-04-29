package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/FishLeaks/FishLeaks/pkg/cleaner"
	"github.com/FishLeaks/FishLeaks/pkg/hunter"
	"github.com/spf13/cobra"
)

var (
	version = "dev"
)

func main() {
	var dir string
	var secretDisplay, redact bool

	rootCmd := &cobra.Command{
		Use:     "fishleaks",
		Short:   "FishLeaks – scan a directory for leaked secrets",
		Long:    "FishLeaks runs GitLeaks and TruffleHog against a target directory and prints de-duplicated findings.",
		Version: version,
		RunE: func(cmd *cobra.Command, args []string) error {

			fmt.Println("___________.__       .__    .____                  __            ")
			fmt.Println("\\_   _____/|__| _____|  |__ |    |    ____ _____  |  | __  ______")
			fmt.Println(" |    __)  |  |/  ___/  |  \\|    |  _/ __ \\__  \\ |  |/ / /  ___/")
			fmt.Println(" |     \\   |  |\\___ \\|   Y  \\    |__\\  ___/ / __ \\|    <  \\___ \\ ")
			fmt.Println(" \\___  /   |__/____  >___|  /_______ \\___  >____  /__|_ \\/____  >")
			fmt.Println("     \\/            \\/     \\/        \\/   \\/     \\/     \\/     \\/ ")
			fmt.Print("\n\n")

			path, err := filepath.Abs(dir)
			if err != nil {
				return fmt.Errorf("resolving path: %w", err)
			}

			hunters := []hunter.Hunter{
				hunter.NewGitLeaks(),
				hunter.NewTruffleHog(),
			}

			c := cleaner.NewTextCleaner()

			for _, h := range hunters {
				findings, err := h.Hunt(path)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error: %v\n", err)
					continue
				}
				for _, f := range findings {
					if redact {
						if err := c.Clean(f); err != nil {
							fmt.Fprintf(os.Stderr, "Error cleaning finding: %v\n", err)
						}
					}
					if secretDisplay {
						fmt.Printf("File: %s\nLine: %d\nSecret: %s\n\n", f.File, f.Line, f.Secret)
					} else {
						fmt.Printf("File: %s\nLine: %d\n\n", f.File, f.Line)
					}
				}
			}

			return nil
		},
	}

	rootCmd.Flags().StringVarP(&dir, "dir", "d", "", "directory to scan for secrets")
	rootCmd.Flags().BoolVarP(&secretDisplay, "secret", "s", false, "set for displaying secrets")
	rootCmd.Flags().BoolVarP(&redact, "redact", "r", false, "set for redacting secrets")

	_ = rootCmd.MarkFlagRequired("dir")

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
