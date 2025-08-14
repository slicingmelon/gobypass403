package main

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
)

// prints an OSC 52 sequence to copy text
func osc52Copy(s string) {
	b64 := base64.StdEncoding.EncodeToString([]byte(s))
	fmt.Printf("\x1b]52;c;%s\x07", b64)
}

// Creates a clickable hyperlink (works in many modern terminals)
func createClickableLink(text, copyText string) {
	// OSC 8 hyperlink with javascript: protocol (some terminals support this)
	fmt.Printf("\x1b]8;;javascript:navigator.clipboard.writeText('%s')\x1b\\%s\x1b]8;;\x1b\\\n", copyText, text)
}

// Creates a fake button with instructions
func createFakeButton(label, copyText string) {
	fmt.Printf("┌─────────────────┐\n")
	fmt.Printf("│ %s │\n", label)
	fmt.Printf("└─────────────────┘\n")
	fmt.Printf("Press Enter to copy: %s\n", copyText)
}

// Interactive menu
func interactiveMenu() {
	scanner := bufio.NewScanner(os.Stdin)

	fmt.Println("=== OSC52 Copy Test ===")
	fmt.Println()

	// Method 1: Hyperlink (modern terminals like Windows Terminal, iTerm2)
	fmt.Println("Method 1 - Clickable Link (if supported):")
	createClickableLink("[ 📋 Click to Copy ]", "Hello from OSC52!")
	fmt.Println()

	// Method 2: Fake button with Enter
	fmt.Println("Method 2 - Press Enter:")
	createFakeButton("📋 COPY", "Hello from OSC52!")

	for {
		if scanner.Scan() {
			input := strings.TrimSpace(scanner.Text())
			if input == "" {
				// Enter pressed
				fmt.Print("Copying... ")
				osc52Copy("Hello from OSC52!")
				fmt.Println("✓ Copied to clipboard!")
				fmt.Println("Press Enter again to copy, or 'q' to quit:")
			} else if strings.ToLower(input) == "q" {
				fmt.Println("Goodbye!")
				break
			}
		}
	}
}

// Method 4: Mouse reporting (experimental)
func enableMouseReporting() {
	// Enable mouse tracking
	fmt.Print("\x1b[?1000h") // Basic mouse reporting
	fmt.Print("\x1b[?1006h") // SGR mouse mode
}

func disableMouseReporting() {
	fmt.Print("\x1b[?1000l")
	fmt.Print("\x1b[?1006l")
}

// Method 5: Different hyperlink approaches
func tryDifferentLinks() {
	fmt.Println("=== Different Link Tests ===")

	// File protocol link
	fmt.Printf("File link: \x1b]8;;file:///tmp/test\x1b\\📁 File Link\x1b]8;;\x1b\\\n")

	// HTTP link (might be more supported)
	fmt.Printf("HTTP link: \x1b]8;;http://example.com\x1b\\🌐 Web Link\x1b]8;;\x1b\\\n")

	// Data URI approach
	fmt.Printf("Data URI: \x1b]8;;data:text/plain,Hello%%20World\x1b\\📝 Data Link\x1b]8;;\x1b\\\n")

	fmt.Println()
}

// Method 6: Keyboard shortcuts simulation
func createHotkeys() {
	fmt.Println("=== Hotkey Tests ===")
	fmt.Println("Try these keyboard combinations:")
	fmt.Printf("Press \x1b[1mCtrl+C\x1b[0m to copy (if terminal captures it)\n")
	fmt.Printf("Press \x1b[1mAlt+C\x1b[0m for alternative copy\n")
	fmt.Printf("Press \x1b[1mSpace\x1b[0m for quick copy\n")
	fmt.Println()
}

// Method 7: Menu selection
func menuSelection() {
	scanner := bufio.NewScanner(os.Stdin)

	fmt.Println("=== Quick Copy Menu ===")
	fmt.Println("1. Copy 'Hello from OSC52!'")
	fmt.Println("2. Copy current timestamp")
	fmt.Println("3. Copy custom text")
	fmt.Println("q. Quit")
	fmt.Print("Choice: ")

	for scanner.Scan() {
		choice := strings.TrimSpace(scanner.Text())

		switch choice {
		case "1":
			osc52Copy("Hello from OSC52!")
			fmt.Println("✓ Copied: Hello from OSC52!")
		case "2":
			timestamp := fmt.Sprintf("Copied at: %s", "now")
			osc52Copy(timestamp)
			fmt.Println("✓ Copied timestamp!")
		case "3":
			fmt.Print("Enter text to copy: ")
			scanner.Scan()
			text := scanner.Text()
			osc52Copy(text)
			fmt.Printf("✓ Copied: %s\n", text)
		case "q":
			return
		default:
			fmt.Println("Invalid choice!")
		}

		fmt.Print("\nChoice: ")
	}
}

func main() {
	fmt.Println("=== OSC52 Terminal Tests ===")

	// Test different link types
	tryDifferentLinks()

	// Test hotkey suggestions
	createHotkeys()

	// Simple number menu (this should definitely work!)
	menuSelection()
}
