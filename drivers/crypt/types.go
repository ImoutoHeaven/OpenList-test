package crypt

const (
	// DataBlockSize is the plaintext payload length per encrypted block.
	DataBlockSize = 64 * 1024
	// DataBlockHeaderSize is the per-block overhead added by secretbox.
	DataBlockHeaderSize = 16
	// FileHeaderSize is the length of the crypt file header (magic + nonce).
	FileHeaderSize = fileHeaderSize
)
