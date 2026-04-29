package cleaner

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func sedSubstitute(filename, oldText, newText string) error {
    data, err := os.ReadFile(filename)
    if err != nil {
        return fmt.Errorf("reading file: %w", err)
    }

    updated := strings.ReplaceAll(string(data), oldText, newText)

    // Write to temp file in same dir (ensures same filesystem for rename)
    tmpFile, err := os.CreateTemp(filepath.Dir(filename), ".tmp-*")
    if err != nil {
        return fmt.Errorf("creating temp file: %w", err)
    }
    tmpName := tmpFile.Name()

    // Cleanup temp file on failure
    defer func() {
        tmpFile.Close()
        os.Remove(tmpName) // no-op if rename succeeded
    }()

    // Copy original file permissions
    info, err := os.Stat(filename)
    if err != nil {
        return fmt.Errorf("stat file: %w", err)
    }

    if err := os.Chmod(tmpName, info.Mode()); err != nil {
        return fmt.Errorf("chmod temp file: %w", err)
    }

    if _, err := tmpFile.WriteString(updated); err != nil {
        return fmt.Errorf("writing temp file: %w", err)
    }

    if err := tmpFile.Close(); err != nil {
        return fmt.Errorf("closing temp file: %w", err)
    }

    // Atomic swap
    if err := os.Rename(tmpName, filename); err != nil {
        return fmt.Errorf("renaming temp file: %w", err)
    }

    return nil
}