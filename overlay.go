// Copyright 2022 Saferwall. All rights reserved.
// Use of this source code is governed by Apache v2 license
// license that can be found in the LICENSE file.

package pe

import (
	"bytes"
	"errors"
	"io"
)

var (
	ErrNoOverlayFound = errors.New("pe does not have overlay data")
)

// NewOverlayReader returns a new ReadSeeker reading the PE overlay data.
func (pe *File) NewOverlayReader() (*io.SectionReader, error) {
	if pe.data == nil {
		return nil, errors.New("pe: file reader is nil")
	}
	rd := bytes.NewReader(pe.data)
	return io.NewSectionReader(rd, pe.OverlayOffset, 1<<63-1), nil
}

// Overlay returns the overlay of the PE file.
func (pe *File) Overlay() ([]byte, error) {
	sr, err := pe.NewOverlayReader()
	if err != nil {
		return nil, err
	}

	overlay := make([]byte, int64(pe.size)-pe.OverlayOffset)
	n, err := sr.ReadAt(overlay, 0)
	if n == len(overlay) {
		pe.HasOverlay = true
		err = nil
	}

	return overlay, err
}

func (pe *File) OverlayLength() int64 {
	return int64(pe.size) - pe.OverlayOffset
}
