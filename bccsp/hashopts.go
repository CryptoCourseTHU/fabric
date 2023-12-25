// SPDX-License-Identifier: Apache-2.0

package bccsp

import "fmt"

// SHA256Opts contains options relating to SHA-256.
type SHA256Opts struct{}

// Algorithm returns the hash algorithm identifier (to be used).
func (opts *SHA256Opts) Algorithm() string {
	return SHA256
}

// SHA384Opts contains options relating to SHA-384.
type SHA384Opts struct{}

// Algorithm returns the hash algorithm identifier (to be used).
func (opts *SHA384Opts) Algorithm() string {
	return SHA384
}

// SHA3_256Opts contains options relating to SHA3-256.
type SHA3_256Opts struct{}

// Algorithm returns the hash algorithm identifier (to be used).
func (opts *SHA3_256Opts) Algorithm() string {
	return SHA3_256
}

// SHA3_384Opts contains options relating to SHA3-384.
type SHA3_384Opts struct{}

// Algorithm returns the hash algorithm identifier (to be used).
func (opts *SHA3_384Opts) Algorithm() string {
	return SHA3_384
}

// SM3Opts contains options relating to SM3.
type SM3Opts struct{}

// Algorithm returns the hash algorithm identifier (to be used).
func (opts *SM3Opts) Algorithm() string {
	return SM3
}

// GetHashOpt returns the HashOpts corresponding to the passed hash function
func GetHashOpt(hashFunction string) (HashOpts, error) {
	switch hashFunction {
	case SHA256:
		return &SHA256Opts{}, nil
	case SHA384:
		return &SHA384Opts{}, nil
	case SHA3_256:
		return &SHA3_256Opts{}, nil
	case SHA3_384:
		return &SHA3_384Opts{}, nil
	case SM3:
		return &SM3Opts{}, nil
	}
	return nil, fmt.Errorf("hash function not recognized [%s]", hashFunction)
}
