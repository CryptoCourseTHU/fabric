/*
Copyright IBM Corp. 2017 All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package factory

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGMFactoryName(t *testing.T) {
	f := &GMFactory{}
	require.Equal(t, f.Name(), SoftwareBasedFactoryName)
}

func TestGMFactoryGetInvalidArgs(t *testing.T) {
	f := &GMFactory{}

	_, err := f.Get(nil)
	require.Error(t, err, "Invalid config. It must not be nil.")

	_, err = f.Get(&FactoryOpts{})
	require.Error(t, err, "Invalid config. It must not be nil.")

	opts := &FactoryOpts{
		SW: &SwOpts{},
	}
	_, err = f.Get(opts)
	require.Error(t, err, "CSP:500 - Failed initializing configuration at [0,]")
}

func TestGMFactoryGet(t *testing.T) {
	f := &SWFactory{}

	opts := &FactoryOpts{
		SW: &SwOpts{
			Security: 256,
			Hash:     "SM3",
		},
	}
	csp, err := f.Get(opts)
	require.NoError(t, err)
	require.NotNil(t, csp)

	opts = &FactoryOpts{
		SW: &SwOpts{
			Security:     256,
			Hash:         "SM3",
			FileKeystore: &FileKeystoreOpts{KeyStorePath: os.TempDir()},
		},
	}
	csp, err = f.Get(opts)
	require.NoError(t, err)
	require.NotNil(t, csp)
}
