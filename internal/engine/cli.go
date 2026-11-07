package engine

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	goruntime "runtime"

	"xrayrelay/internal/model"
)

func dispatchNode(ctx context.Context, req nodeRequest) (nodeResponse, error) {
	switch req.Operation {
	case "inspect":
		i, err := inspectNode(ctx)
		return nodeResponse{Inspection: &i}, err
	case "apply":
		r, err := applyNode(ctx, req)
		return nodeResponse{Apply: &r}, err
	case "probe":
		r, err := probeNode(ctx, req)
		return nodeResponse{Probe: &r}, err
	case "service":
		return nodeResponse{}, serviceNode(ctx, req.Action)
	case "logs":
		s, err := logsNode(ctx)
		return nodeResponse{Logs: s}, err
	default:
		return nodeResponse{}, errors.New("unsupported node operation")
	}
}

// RunNodeCLI is also the trusted, versioned helper protocol used over SSH.
// Secrets arrive on stdin or in a private request file, never as process arguments.
func RunNodeCLI(ctx context.Context, args []string, in io.Reader, out, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: xray-panel-nodectl helper | inspect | logs | service <start|stop|restart|rollback> | apply --config FILE --version TAG [--archive ZIP --sha256 HEX] | probe --request FILE")
		return 2
	}
	var req nodeRequest
	switch args[0] {
	case "version":
		fmt.Fprintln(out, model.Version)
		return 0
	case "helper":
		if len(args) != 1 {
			fmt.Fprintln(stderr, "helper accepts a JSON request on stdin only")
			return 2
		}
		decoder := json.NewDecoder(io.LimitReader(in, maxImportConfig+1))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&req); err != nil {
			_ = json.NewEncoder(out).Encode(nodeResponse{Error: "invalid node helper request"})
			return 0
		}
		if err := decoder.Decode(new(any)); err != io.EOF {
			_ = json.NewEncoder(out).Encode(nodeResponse{Error: "trailing node helper input"})
			return 0
		}
	case "inspect", "logs":
		if len(args) != 1 {
			fmt.Fprintln(stderr, "unexpected arguments")
			return 2
		}
		req.Operation = args[0]
	case "service":
		if len(args) != 2 {
			fmt.Fprintln(stderr, "service requires start, stop, restart or rollback")
			return 2
		}
		req.Operation = "service"
		req.Action = args[1]
	case "apply":
		flags := flag.NewFlagSet("apply", flag.ContinueOnError)
		flags.SetOutput(stderr)
		config := flags.String("config", "", "candidate config JSON file")
		version := flags.String("version", model.DefaultCoreVersion, "explicit official core tag")
		archive := flags.String("archive", "", "verified official release archive")
		checksum := flags.String("sha256", "", "official release SHA256")
		if flags.Parse(args[1:]) != nil || flags.NArg() != 0 || *config == "" {
			return 2
		}
		b, err := readPrivateFile(*config, maxImportConfig)
		if err != nil {
			fmt.Fprintln(stderr, "could not read candidate config")
			return 1
		}
		req = nodeRequest{Operation: "apply", Version: *version, Architecture: goruntime.GOARCH, Archive: *archive, SHA256: *checksum, Config: b}
	case "probe":
		flags := flag.NewFlagSet("probe", flag.ContinueOnError)
		flags.SetOutput(stderr)
		path := flags.String("request", "", "private JSON node request file")
		if flags.Parse(args[1:]) != nil || flags.NArg() != 0 || *path == "" {
			return 2
		}
		b, err := readPrivateFile(*path, maxImportConfig)
		if err != nil || json.Unmarshal(b, &req) != nil {
			fmt.Fprintln(stderr, "invalid private probe request file")
			return 1
		}
		req.Operation = "probe"
	default:
		fmt.Fprintln(stderr, "unknown nodectl command")
		return 2
	}
	response, err := dispatchNode(ctx, req)
	if err != nil {
		response.Error = err.Error()
	}
	if encodeErr := json.NewEncoder(out).Encode(response); encodeErr != nil {
		return 1
	}
	if err != nil && args[0] != "helper" {
		return 1
	}
	return 0
}
func readPrivateFile(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if len(b) > int(limit) {
		return nil, errors.New("request file exceeds limit")
	}
	return b, err
}
