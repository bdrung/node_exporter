// Copyright 2021 The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package collector

import (
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"sync"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	envparse "github.com/hashicorp/go-envparse"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	etcOSRelease    = "/etc/os-release"
	usrLibOSRelease = "/usr/lib/os-release"
	versionRegex    = regexp.MustCompile(`^[0-9]+\.?[0-9]*`)
)

type osRelease struct {
	Name            string
	ID              string
	IDLike          string
	PrettyName      string
	Variant         string
	VariantID       string
	Version         string
	VersionID       string
	VersionCodename string
	BuildID         string
	ImageID         string
	ImageVersion    string
}

type osReleaseCollector struct {
	infoDesc             *prometheus.Desc
	logger               log.Logger
	mtimeEtcOSRelease    time.Time
	mtimeUsrLibOSRelease time.Time
	os                   *osRelease
	osMutex              sync.Mutex
	version              float64
	versionDesc          *prometheus.Desc
}

func init() {
	registerCollector("os", defaultEnabled, NewOSCollector)
}

// NewOSCollector returns a new Collector exposing os-release information.
func NewOSCollector(logger log.Logger) (Collector, error) {
	return &osReleaseCollector{
		logger: logger,
		infoDesc: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "os", "info"),
			"A metric with a constant '1' value labeled by build_id, id, id_like, image_id, image_version, "+
				"name, pretty_name, variant, variant_id, version, version_codename, version_id.",
			[]string{"build_id", "id", "id_like", "image_id", "image_version", "name", "pretty_name",
				"variant", "variant_id", "version", "version_codename", "version_id"}, nil,
		),
		versionDesc: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "os", "version"),
			"Metric containing the major.minor part of the OS version.",
			nil, nil,
		),
	}, nil
}

func parseOSRelease(r io.Reader) (*osRelease, error) {
	env, err := envparse.Parse(r)
	return &osRelease{
		Name:            env["NAME"],
		ID:              env["ID"],
		IDLike:          env["ID_LIKE"],
		PrettyName:      env["PRETTY_NAME"],
		Variant:         env["VARIANT"],
		VariantID:       env["VARIANT_ID"],
		Version:         env["VERSION"],
		VersionID:       env["VERSION_ID"],
		VersionCodename: env["VERSION_CODENAME"],
		BuildID:         env["BUILD_ID"],
		ImageID:         env["IMAGE_ID"],
		ImageVersion:    env["IMAGE_VERSION"],
	}, err
}

func (c *osReleaseCollector) updateIfChanged(f *os.File, mtime *time.Time) error {
	stat, err := f.Stat()
	if err != nil {
		return err
	}

	t := stat.ModTime()
	if t != *mtime {
		level.Debug(c.logger).Log("msg", "file modification time has changed",
			"file", f.Name(), "old_value", mtime, "new_value", t)
		*mtime = t

		// Acquire a lock to update the osReleaseCollector struct.
		c.osMutex.Lock()
		defer c.osMutex.Unlock()

		c.os, err = parseOSRelease(f)
		if err != nil {
			return err
		}
		majorMinor := versionRegex.FindString(c.os.VersionID)
		if majorMinor != "" {
			c.version, err = strconv.ParseFloat(majorMinor, 64)
			if err != nil {
				return err
			}
		} else {
			c.version = 0
		}
	}
	return nil
}

func (c *osReleaseCollector) UpdateStruct() error {
	etcOSReleaseFile, err := os.Open(*rootfsPath + etcOSRelease)
	if err == nil {
		defer etcOSReleaseFile.Close()
		return c.updateIfChanged(etcOSReleaseFile, &c.mtimeEtcOSRelease)
	}

	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	c.mtimeEtcOSRelease = time.Time{}

	// Fall back to /usr/lib/os-release if /etc/os-release is not present
	usrLibOSReleaseFile, err := os.Open(*rootfsPath + usrLibOSRelease)
	if err == nil {
		defer usrLibOSReleaseFile.Close()
		return c.updateIfChanged(usrLibOSReleaseFile, &c.mtimeUsrLibOSRelease)
	}

	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return fmt.Errorf("Neither %s nor %s exists: %w", etcOSReleaseFile.Name(), usrLibOSReleaseFile.Name(), err)
}

func (c *osReleaseCollector) Update(ch chan<- prometheus.Metric) error {
	err := c.UpdateStruct()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			level.Debug(c.logger).Log("msg", "no os-release file found, skipping")
			return ErrNoData
		}
		return err
	}
	ch <- prometheus.MustNewConstMetric(c.infoDesc, prometheus.GaugeValue, 1.0,
		c.os.BuildID, c.os.ID, c.os.IDLike, c.os.ImageID, c.os.ImageVersion, c.os.Name, c.os.PrettyName,
		c.os.Variant, c.os.VariantID, c.os.Version, c.os.VersionCodename, c.os.VersionID)
	if c.version > 0 {
		ch <- prometheus.MustNewConstMetric(c.versionDesc, prometheus.GaugeValue, c.version)
	}
	return nil
}
