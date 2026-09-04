module github.com/redivers/sdk-go

go 1.25.0

require (
	buf.build/gen/go/rediver/api/connectrpc/go v1.20.0-20260903033529-8f150629bfd3.1
	buf.build/gen/go/rediver/api/protocolbuffers/go v1.36.12-20260903033529-8f150629bfd3.1
	connectrpc.com/connect v1.20.0
	golang.org/x/net v0.56.0
	google.golang.org/protobuf v1.36.12
)

require golang.org/x/text v0.38.0 // indirect
