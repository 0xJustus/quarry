package backend

import (
	"regexp"
	"strings"
)

var (
	reJVMException = regexp.MustCompile(`Exception in thread "[^"]*"\s+([\w.$]+(?:Exception|Error))`)
	// Jazzer prints faults in its own banner, not the stock JVM line
	reJazzerException = regexp.MustCompile(`== Java Exception:\s+([\w.$]+(?:Exception|Error))`)
	reJVMFrame        = regexp.MustCompile(`(?m)^\s*at\s+(\S+)`)

	rePyException = regexp.MustCompile(`(?m)^([A-Za-z_][\w.]*(?:Error|Exception|Warning|Interrupt))(?::.*)?$`)
	rePyFrame     = regexp.MustCompile(`(?m)^\s*File "([^"]+)", line (\d+), in (\S+)`)

	reGoPanic = regexp.MustCompile(`(?m)^panic:\s+(.*)$`)
	reGoFatal = regexp.MustCompile(`(?m)^fatal error:\s+(.*)$`)
	reGoFrame = regexp.MustCompile(`(?m)^\s+(\S+\.go:\d+)`)

	reRustPanicLoc = regexp.MustCompile(`panicked at (\S+:\d+:\d+)`)
	reRustASan     = regexp.MustCompile(`ERROR: AddressSanitizer: (\S+)`)

	// anchored after the banner so the word "Exception" in it is not captured
	reJSJazzer  = regexp.MustCompile(`Uncaught Exception:\s+([A-Za-z_$][\w$.]*)`)
	reJSNodeErr = regexp.MustCompile(`(?m)^([A-Z][A-Za-z0-9_]*(?:Error|Exception)|Error|Exception):`)
	reJSFrame   = regexp.MustCompile(`(?m)^\s*at\s+.*?\(?([^\s()]+:\d+:\d+)\)?`)

	rePHPException = regexp.MustCompile(`(?m)(?:Uncaught\s+)?\\?([A-Za-z_][A-Za-z0-9_\\]*(?:Exception|Error))\b`)
	rePHPSite      = regexp.MustCompile(`in\s+(\S+:\d+)`)
)

func ClassifyJVM(out string) Fault {
	m := reJVMException.FindStringSubmatch(out)
	if m == nil {
		m = reJazzerException.FindStringSubmatch(out)
	}
	if m == nil {
		return Fault{Faulted: false, Class: FaultNone}
	}
	cls := m[1]
	site := ""
	if fm := reJVMFrame.FindStringSubmatch(out); fm != nil {
		site = strings.TrimSpace(fm[1])
	}
	class := FaultException
	if strings.Contains(cls, "StackOverflowError") || strings.Contains(cls, "OutOfMemoryError") {
		class = FaultTimeout
	}
	return Fault{Faulted: true, Class: class, Signal: cls, Site: site}
}

func ClassifyPython(out string) Fault {
	if !strings.Contains(out, "Traceback (most recent call last)") {
		return Fault{Faulted: false, Class: FaultNone}
	}
	ms := rePyException.FindAllStringSubmatch(out, -1)
	if len(ms) == 0 {
		return Fault{Faulted: false, Class: FaultNone}
	}
	cls := ms[len(ms)-1][1] // last match: the raised type is the final line of a traceback
	site := ""
	if fm := rePyFrame.FindAllStringSubmatch(out, -1); len(fm) > 0 {
		last := fm[len(fm)-1] // deepest frame: where it was raised
		site = last[3] + " (" + last[1] + ":" + last[2] + ")"
	}
	class := FaultException
	if cls == "RecursionError" || cls == "MemoryError" {
		class = FaultTimeout
	}
	return Fault{Faulted: true, Class: class, Signal: cls, Site: site}
}

func ClassifyGo(out string) Fault {
	if fm := reGoFatal.FindStringSubmatch(out); fm != nil {
		msg := strings.TrimSpace(fm[1])
		class := FaultException
		if strings.Contains(msg, "out of memory") || strings.Contains(msg, "stack overflow") {
			class = FaultTimeout
		}
		return Fault{Faulted: true, Class: class, Signal: "fatal: " + msg, Site: goSite(out)}
	}
	if m := reGoPanic.FindStringSubmatch(out); m != nil {
		return Fault{Faulted: true, Class: FaultException, Signal: strings.TrimSpace(m[1]), Site: goSite(out)}
	}
	return Fault{Faulted: false, Class: FaultNone}
}

func goSite(out string) string {
	if fm := reGoFrame.FindStringSubmatch(out); fm != nil {
		return strings.TrimSpace(fm[1])
	}
	return ""
}

func ClassifyRust(out string) Fault {
	// ASan first: libFuzzer also prints "deadly signal" for a panic, which is NOT memory
	if m := reRustASan.FindStringSubmatch(out); m != nil {
		return Fault{Faulted: true, Class: FaultMemory, Signal: m[1], Site: rustPanicSite(out)}
	}
	loc := reRustPanicLoc.FindStringSubmatch(out)
	if loc == nil {
		return Fault{Faulted: false, Class: FaultNone}
	}
	class := FaultException
	if strings.Contains(out, "stack overflow") || strings.Contains(out, "memory allocation of") {
		class = FaultTimeout
	}
	sig := "panic"
	if msg := rustPanicMsg(out); msg != "" {
		sig = "panic: " + msg
	}
	return Fault{Faulted: true, Class: class, Signal: sig, Site: loc[1]}
}

func rustPanicSite(out string) string {
	if m := reRustPanicLoc.FindStringSubmatch(out); m != nil {
		return m[1]
	}
	return ""
}

func rustPanicMsg(out string) string {
	lines := strings.Split(out, "\n")
	for i, ln := range lines {
		if strings.Contains(ln, "panicked at ") && i+1 < len(lines) {
			return strings.TrimSpace(lines[i+1])
		}
	}
	return ""
}

func ClassifyJS(out string) Fault {
	var cls string
	if m := reJSJazzer.FindStringSubmatch(out); m != nil {
		cls = m[1]
	} else if m := reJSNodeErr.FindStringSubmatch(out); m != nil {
		cls = m[1]
	} else {
		return Fault{Faulted: false, Class: FaultNone}
	}
	class := FaultException
	if strings.Contains(out, "Maximum call stack size exceeded") || strings.Contains(out, "heap out of memory") || strings.Contains(out, "JavaScript heap out of memory") {
		class = FaultTimeout
	}
	site := ""
	if fm := reJSFrame.FindStringSubmatch(out); fm != nil {
		site = fm[1]
	}
	return Fault{Faulted: true, Class: class, Signal: cls, Site: site}
}

func ClassifyPHP(out string) Fault {
	m := rePHPException.FindStringSubmatch(out)
	if m == nil {
		return Fault{Faulted: false, Class: FaultNone}
	}
	cls := strings.TrimPrefix(m[1], "\\")
	site := ""
	if sm := rePHPSite.FindStringSubmatch(out); sm != nil {
		site = sm[1]
	}
	return Fault{Faulted: true, Class: FaultException, Signal: cls, Site: site}
}
