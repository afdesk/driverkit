package driverbuilder

import (
	"archive/tar"
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/client"
	"github.com/falcosecurity/driverkit/pkg/driverbuilder/builder"
	"github.com/falcosecurity/driverkit/pkg/signals"
	"github.com/sirupsen/logrus"
	logger "github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/util/uuid"
)

// DockerBuildProcessorName is a constant containing the docker name.
const DockerBuildProcessorName = "docker"

type DockerBuildProcessor struct {
	clean   bool
	timeout int
	proxy   string
}

// NewDockerBuildProcessor ...
func NewDockerBuildProcessor(timeout int, proxy string) *DockerBuildProcessor {
	return &DockerBuildProcessor{
		timeout: timeout,
		proxy:   proxy,
	}
}

func (bp *DockerBuildProcessor) String() string {
	return DockerBuildProcessorName
}

// Start the docker processor
func (bp *DockerBuildProcessor) Start(b *builder.Build) error {
	logger.Debug("doing a new docker build")
	cli, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		return err
	}

	driverName := "falco"
	deviceName := "falco"
	isDefault := true
	if  b.BuilderImage != "" {
		isDefault = false
		driverName = "custom"
		deviceName = "custom"
		builderBaseImage = b.BuilderImage
	}
	// create a builder based on the choosen build type
	v, err := builder.Factory(b.TargetType)
	if err != nil {
		return err
	}
	c := builder.Config{
		DriverName:      driverName,
		DeviceName:      deviceName,
		DownloadBaseURL: "https://github.com/falcosecurity/libs/archive",
		Build:           b,
	}
	// Generate the build script from the builder
	res, err := v.Script(c)
	if err != nil {
		return err
	}
	files := []dockerCopyFile{
		{"/driverkit/driverkit.sh", res},
	}

	if isDefault {
		// Prepare driver config template
		bufDriverConfig := bytes.NewBuffer(nil)
		err = renderDriverConfig(bufDriverConfig, driverConfigData{DriverVersion: c.DriverVersion, DriverName: c.DriverName, DeviceName: c.DeviceName})
		if err != nil {
			return err
		}
		files = append(files, dockerCopyFile{"/driverkit/module-driver-config.h", bufDriverConfig.String()})

		// Prepare makefile template
		bufMakefile := bytes.NewBuffer(nil)
		err = renderMakefile(bufMakefile, makefileData{ModuleName: c.DriverName, ModuleBuildDir: builder.DriverDirectory})
		if err != nil {
			return err
		}
		files = append(files, dockerCopyFile{"/driverkit/module-Makefile", bufMakefile.String()})

		configDecoded, err := base64.StdEncoding.DecodeString(b.KernelConfigData)
		if err != nil {
			return err
		}
		files = append(files, dockerCopyFile{"/driverkit/kernel.config", string(configDecoded)})
	}
	// Create the container
	ctx := context.Background()
	ctx = signals.WithStandardSignals(ctx)

	if _, _, err = cli.ImageInspectWithRaw(ctx, builderBaseImage); client.IsErrNotFound(err) {
		logger.WithField("image", builderBaseImage).Debug("pulling builder image")
		pullRes, err := cli.ImagePull(ctx, builderBaseImage, types.ImagePullOptions{})
		if err != nil {
			return err
		}
		defer pullRes.Close()
		_, err = io.Copy(ioutil.Discard, pullRes)
		if err != nil {
			return err
		}
	}

	containerCfg := &container.Config{
		Tty:   true,
		Cmd:   []string{"/bin/sleep", strconv.Itoa(bp.timeout)},
		Image: builderBaseImage,
	}

	hostCfg := &container.HostConfig{
		AutoRemove: false,
	}
	networkCfg := &network.NetworkingConfig{}
	uid := uuid.NewUUID()
	name := fmt.Sprintf("driverkit-%s", string(uid))
	cdata, err := cli.ContainerCreate(ctx, containerCfg, hostCfg, networkCfg, name)
	if err != nil {
		return err
	}

	defer bp.cleanup(ctx, cli, cdata.ID)
	go func() {
		for {
			select {
			case <-ctx.Done():
				bp.cleanup(ctx, cli, cdata.ID)
				return
			}
		}
	}()

	err = cli.ContainerStart(ctx, cdata.ID, types.ContainerStartOptions{})
	if err != nil {
		return err
	}

	var buf bytes.Buffer
	err = tarWriterFiles(&buf, files)
	if err != nil {
		return err
	}

	// Copy the needed files to the container
	err = cli.CopyToContainer(ctx, cdata.ID, "/", &buf, types.CopyToContainerOptions{})
	if err != nil {
		return err
	}

	// Construct environment variable array of string
	var envs []string
	// Add http_proxy and https_proxy environment variable
	if bp.proxy != "" {
		envs = append(envs,
			fmt.Sprintf("http_proxy=%s", bp.proxy),
			fmt.Sprintf("https_proxy=%s", bp.proxy),
		)
	}

	edata, err := cli.ContainerExecCreate(ctx, cdata.ID, types.ExecConfig{
		Privileged:   false,
		Tty:          false,
		AttachStdin:  false,
		AttachStderr: true,
		AttachStdout: true,
		Detach:       true,
		Env:          envs,
		Cmd: []string{
			"/bin/bash",
			"/driverkit/driverkit.sh",
		},
	})

	if err != nil {
		return err
	}

	hr, err := cli.ContainerExecAttach(ctx, edata.ID, types.ExecStartCheck{})
	if err != nil {
		return err
	}
	defer hr.Close()

	forwardLogs(hr.Reader)

	if len(b.ModuleFilePath) > 0 {
		if err := copyFromContainer(ctx, cli, cdata.ID, builder.FalcoModuleFullPath, b.ModuleFilePath); err != nil {
			return err
		}
		logrus.WithField("path", b.ModuleFilePath).Info("kernel module available")
	}

	if len(b.ProbeFilePath) > 0 {
		if err := copyFromContainer(ctx, cli, cdata.ID, builder.FalcoProbeFullPath, b.ProbeFilePath); err != nil {
			return err
		}
		logrus.WithField("path", b.ProbeFilePath).Info("eBPF probe available")
	}

	return nil
}

func copyFromContainer(ctx context.Context, cli *client.Client, ID, from, to string) error {
	rc, _, err := cli.CopyFromContainer(ctx, ID, from)
	if err != nil {
		return err
	}
	defer rc.Close()

	tr := tar.NewReader(rc)

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			logger.WithError(err).Error("error expanding tar")
		}

		if hdr.Name == filepath.Base(from) {
			out, err := os.Create(to)

			if err != nil {
				return err
			}
			defer out.Close()

			_, err = io.Copy(out, tr)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (bp *DockerBuildProcessor) cleanup(ctx context.Context, cli *client.Client, ID string) {
	if !bp.clean {
		bp.clean = true
		logger.Debug("context canceled")
		duration := time.Duration(time.Second)
		if err := cli.ContainerStop(context.Background(), ID, &duration); err != nil {
			logger.WithError(err).WithField("container_id", ID).Error("error stopping container")
		}
	}
}

type dockerCopyFile struct {
	Name string
	Body string
}

func tarWriterFiles(buf io.Writer, files []dockerCopyFile) error {
	tw := tar.NewWriter(buf)
	defer tw.Close()
	for _, file := range files {
		hdr := &tar.Header{
			Name: file.Name,
			Mode: 0600,
			Size: int64(len(file.Body)),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if _, err := tw.Write([]byte(file.Body)); err != nil {
			return err
		}
	}
	return nil
}

func forwardLogs(logPipe io.Reader) {
	lineReader := bufio.NewReader(logPipe)
	for {
		line, err := lineReader.ReadBytes('\n')
		if len(line) > 0 {
			logger.Debugf("%s", line)
		}
		if err == io.EOF {
			logger.WithError(err).Debug("log pipe close")
			return
		}
		if err != nil {
			logger.WithError(err).Error("log pipe error")
		}
	}
}
