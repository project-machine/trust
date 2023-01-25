all: trust

trust: cmd/trust/*.go pkg/trust/*.go
	go build -o trust ./cmd/trust/

clean:
	rm -f trust
