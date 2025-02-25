package builder

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/falcosecurity/driverkit/pkg/kernelrelease"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"text/template"
)

const mainlineUrl = "http://kernel.ubuntu.com/~kernel-ppa/mainline/v"

var errFailedKernelRelease = errors.New("failed kernel release for ubuntu mainline")
var errFailedDownloadLink = errors.New("failed download link from ubuntu mainline")

const shellMainlineTemplate = `#!/bin/bash
rm -Rf {{ .DriverBuildDir }}
mkdir {{ .DriverBuildDir }}
cd {{ .DriverBuildDir }}
mkdir bpf
{{range $url := .KernelDownloadURLS}}
curl --silent -o kernel.deb -SL {{ $url }}
ar x kernel.deb
tar -xf data.tar.*
{{end}}
cd /tracee
KERN_HEADERS={{ .DriverBuildDir }}/usr/src/{{ .KernelHeadersPattern }} KERN_RELEASE=generic make bpf
cp /tracee/dist/tracee.bpf.generic.0.o /tmp/driver/bpf/probe.o`

type ubuntuMainline struct {}

func (ubnt *ubuntuMainline) Script(c Config) (string, error) {
	t := template.New(string(TargetTypeUbuntuGeneric))
	parsed, err := t.Parse(shellMainlineTemplate)
	if err != nil {
		return "", err
	}

	urls, kr, err := ubuntuGenericHeadersURLFromMainline(c.Build.KernelRelease)
	if err != nil {
		return "", err
	}

	td := ubuntuTemplateData{
		DriverBuildDir:       DriverDirectory,
		ModuleDownloadURL:    fmt.Sprintf("%s/%s.tar.gz", c.DownloadBaseURL, c.Build.DriverVersion),
		KernelDownloadURLS:   urls,
		KernelLocalVersion:   kr.FullExtraversion,
		KernelHeadersPattern: "linux-headers*generic",
		BuildModule:          len(c.Build.ModuleFilePath) > 0,
		BuildProbe:           len(c.Build.ProbeFilePath) > 0,
		GCCVersion:           ubuntuGCCVersionFromKernelRelease(kr),
	}
	buf := bytes.NewBuffer(nil)
	err = parsed.Execute(buf, td)
	if err != nil {
		return "", err
	}
	return buf.String(), nil
}

type ubuntuMainlineVersion struct {
	KernelRelease      string
	KernelVersion      string
	MajorVersion       string
	MinorVersion       string
	SpecificAdditional string
}

func fetchPage(url string) ([]byte, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var buff bytes.Buffer
	io.Copy(&buff, resp.Body)

	return buff.Bytes(), err
}

func getPatchFromAll(in string) string {
	prefix := "."
	suffix := "_all"
	pattern := fmt.Sprintf("\\%s[0-9]+%s", prefix, suffix)
	re := regexp.MustCompile(pattern)
	s := string(re.Find([]byte(in)))
	return strings.TrimSuffix(strings.TrimPrefix(s, prefix), suffix)
}

func getArchFromAll(in string) string {
	s := strings.Split(in, "/")
	if len(s) > 1 {
		return s[0]
	}
	return ""
}

func genCurrentLink(v *ubuntuMainlineVersion, patch, arch string) (link string, dir string) {
	isArch := ""
	if arch != "" {
		isArch = "/"
	}
	vers, _ := strconv.Atoi(v.KernelVersion)
	mj, _ := strconv.Atoi(v.MajorVersion)
	mi, _ := strconv.Atoi(v.MinorVersion)

	code := fmt.Sprintf("%02d%02d%02d%s", vers, mj, mi, v.SpecificAdditional)

	dir = fmt.Sprintf("linux-headers-%s.%s.%d-%s-generic", v.KernelVersion, v.MajorVersion, mi, code)

	link = fmt.Sprintf("%s%slinux-headers-%s.%s.%d-%s-generic_%[3]s.%[4]s.%[5]d-%[6]s.%s_amd64.deb",
		arch, isArch, v.KernelVersion, v.MajorVersion, mi, code, patch)
	return
}
func fetchLinks(v *ubuntuMainlineVersion) (linkAll string, linkCurrent string, dir string, err error) {
	base := fmt.Sprintf("%s%s/", mainlineUrl, v.KernelRelease)

	page, err := fetchPage(base)
	if err != nil {
		return "", "", "", err
	}

	prefix := "<a href=\""
	suffix := "_all.deb\">"
	patternAll := fmt.Sprintf("%s[0-9a-z_\\/.-]+%s", prefix, suffix)
	re := regexp.MustCompile(patternAll)
	link := strings.TrimSuffix(strings.TrimPrefix(string(re.Find(page)), prefix), "\">")
	patch := getPatchFromAll(link)
	arch := getArchFromAll(link)

	linkAll = base + link
	linkCurrent, dir = genCurrentLink(v, patch, arch)
	linkCurrent = base + linkCurrent
	return
}

func getMainlineVersion(release string) (*ubuntuMainlineVersion, error) {
	s := strings.Split(release, "-")
	if len(s) == 0 {
		return nil, errFailedKernelRelease
	}
	versions := strings.Split(s[0], ".")
	if l := len(versions); l < 2 || l > 3 {
		return nil, errFailedKernelRelease
	}
	minor := ""
	if len(versions) == 3 {
		minor = versions[2]
	}
	specific := ""
	if len(s) > 1 {
		specific = strings.Join(s[1:], "-")
	}
	return &ubuntuMainlineVersion{
		KernelRelease:      release,
		KernelVersion:      versions[0],
		MajorVersion:       versions[1],
		MinorVersion:       minor,
		SpecificAdditional: specific,
	}, nil
}

func ubuntuGenericHeadersURLFromMainline(fullVersion string) ([]string, kernelrelease.KernelRelease, error) {
	kr := kernelrelease.KernelRelease{}

	kmv, err := getMainlineVersion(fullVersion)
	if err != nil {
		return nil, kr, err
	}

	all, current, _, err := fetchLinks(kmv)
	if err != nil {
		return nil, kr, err
	}

	resp, err := http.Head(all)
	if err != nil {
		return nil, kr, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, kr, errFailedDownloadLink
	}
	resp, err = http.Head(current)
	if err != nil {
		return nil, kr, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, kernelrelease.KernelRelease{}, errFailedDownloadLink
	}

	urls := []string{all, current}
	kr.Fullversion = fullVersion
	kr.Version = kmv.KernelVersion
	kr.PatchLevel = kmv.MajorVersion
	kr.Sublevel = kmv.MinorVersion
	kr.Extraversion = kmv.SpecificAdditional
	kr.FullExtraversion = fmt.Sprintf("-%s", kmv.SpecificAdditional)
	return urls, kr, nil
}
