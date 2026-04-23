//go:build !windows && !linux && !android && !darwin && !freebsd

package tun

import "fmt"

type stubFactory struct{}

func NewFactory() Factory {
	return &stubFactory{}
}

func (f *stubFactory) Create(cfg CreateConfig) (Device, error) {
	_ = cfg
	return nil, ErrNotImplemented
}

type stubDevice struct{}

func (d *stubDevice) Name() (string, error) {
	return "", ErrNotImplemented
}

func (d *stubDevice) MTU() int {
	return 0
}

func (d *stubDevice) ReadPacket(buf []byte) (int, error) {
	return 0, ErrNotImplemented
}

func (d *stubDevice) WritePacket(pkt []byte) error {
	return ErrNotImplemented
}

func (d *stubDevice) Close() error {
	return ErrNotImplemented
}

func (d *stubDevice) BatchSize() int {
	return 0
}

func (d *stubDevice) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	return 0, fmt.Errorf("batch read: %w", ErrNotImplemented)
}

func (d *stubDevice) Write(bufs [][]byte, offset int) (int, error) {
	return 0, fmt.Errorf("batch write: %w", ErrNotImplemented)
}

type stubConfigurator struct{}

func NewConfigurator() Configurator {
	return &stubConfigurator{}
}

func (c *stubConfigurator) Setup(cfg NetworkConfig) error {
	_ = cfg
	return ErrNotImplemented
}

func (c *stubConfigurator) Teardown(ifName string) error {
	_ = ifName
	return ErrNotImplemented
}

func (c *stubConfigurator) UpdateAddress(prev, next NetworkConfig) error {
	_ = prev
	_ = next
	return ErrNotImplemented
}
