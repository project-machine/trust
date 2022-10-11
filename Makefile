all: trust

trust: *.go lib/*.go
	go build

clean:
	rm -f trust
