package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

func main() {
	if len(os.Args) > 1 && strings.HasPrefix(os.Args[1], "--mode=") {
		runMode(strings.TrimPrefix(os.Args[1], "--mode="))
		return
	}
	name := strings.ToLower(filepath.Base(os.Args[0]))
	for _, arg := range os.Args[1:] {
		if arg == "--version" {
			_, _ = fmt.Fprintln(os.Stdout, "Nmap version 7.96")
			if strings.Contains(name, "fail") {
				os.Exit(7)
			}
			return
		}
		if arg == "-version" {
			_, _ = fmt.Fprintln(os.Stdout, "Subfaster v2.18.0")
			return
		}
	}
	if name == "nmap" || strings.Contains(name, "nmap-") {
		targets, _ := io.ReadAll(os.Stdin)
		var xml strings.Builder
		xml.WriteString(`<?xml version="1.0"?><nmaprun>`)
		for _, target := range strings.Fields(string(targets)) {
			fmt.Fprintf(&xml, `<host><status state="up"/><address addr="%s" addrtype="ipv4"/><ports><port protocol="tcp" portid="80"><state state="open"/></port></ports></host>`, target)
		}
		xml.WriteString(`<host><status state="up"/><address addr="192.0.2.250" addrtype="ipv4"/><ports><port protocol="tcp" portid="80"><state state="open"/></port></ports></host><runstats><finished exit="success"/></runstats></nmaprun>`)
		_, _ = io.WriteString(os.Stdout, xml.String())
		return
	}
	if name == "subfaster" {
		_, _ = fmt.Fprintln(os.Stdout, `{"host":"app.example.test","sources":["thc"]}`)
		if strings.Contains(strings.Join(os.Args[1:], " "), "rapiddns") {
			time.Sleep(5 * time.Second)
			_, _ = fmt.Fprintln(os.Stdout, `{"host":"later.example.test","sources":["thc"]}`)
		}
		os.Exit(7)
	}
}

func runMode(mode string) {
	switch mode {
	case "stdin":
		_, _ = io.Copy(os.Stdout, os.Stdin)
	case "echo":
		_, _ = io.WriteString(os.Stdout, strings.Join(os.Args[2:], "|")+"|"+os.Getenv("ASM_TEST_SECRET"))
	case "sleep", "hold":
		time.Sleep(10 * time.Second)
	case "overflow":
		for i := 0; i < 1000; i++ {
			_, _ = io.WriteString(os.Stdout, strings.Repeat("x", 1024))
		}
	case "rows":
		_, _ = io.WriteString(os.Stdout, "first\n")
		time.Sleep(100 * time.Millisecond)
		_, _ = io.WriteString(os.Stdout, "second\nthird\n")
	case "fragmented":
		_, _ = io.WriteString(os.Stdout, "a")
		time.Sleep(10 * time.Millisecond)
		_, _ = io.WriteString(os.Stdout, "\nb\nlast")
	case "long-terminated":
		_, _ = io.WriteString(os.Stdout, "12345\n")
	case "long-unterm":
		_, _ = io.WriteString(os.Stdout, "12345")
	case "marker":
		if len(os.Args) > 2 {
			_ = os.WriteFile(os.Args[2], []byte("started"), 0600)
		}
	case "spawn-holding-child":
		cmd := exec.Command(os.Args[0], "--mode=hold")
		cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
		if err := cmd.Start(); err != nil {
			os.Exit(1)
		}
		_, _ = io.WriteString(os.Stdout, "root-exit\n")
	}
}
