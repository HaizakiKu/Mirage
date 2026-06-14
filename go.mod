module github.com/HaizakiKu/mirage

go 1.24

require (
	github.com/HaizakiKu/quic-ech v0.0.0
	github.com/quic-go/quic-go v0.57.1-mirage.1
	github.com/refraction-networking/utls v1.8.2
	golang.org/x/crypto v0.41.0
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/andybalholm/brotli v1.0.6 // indirect
	github.com/klauspost/compress v1.17.4 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/quic-go/qpack v0.6.0 // indirect
	github.com/quic-go/qtls-go1-20 v0.4.1 // indirect
	golang.org/x/exp v0.0.0-20240416160154-fe59bbe5cc7f // indirect
	golang.org/x/net v0.43.0 // indirect
	golang.org/x/sys v0.35.0 // indirect
	golang.org/x/text v0.28.0 // indirect
)

// quic-ech is maintained alongside mirage
replace github.com/HaizakiKu/quic-ech => ./quic-ech

// Fork adds TLSClientConnFactory hook for uTLS Chrome fingerprint injection.
replace github.com/quic-go/quic-go => github.com/HaizakiKu/quic-go v0.57.1-mirage.1
