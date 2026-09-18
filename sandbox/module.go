package sandbox

import (
	"encoding/binary"
	"fmt"
	"math"
	"regexp"
	"time"
)

// Module runs: a compiled physical model (an AOT-compiled WebAssembly module
// baked into the provider's module image) executed once per parameter row by a
// supervised worker. The types here are transport-agnostic, like the rest of the
// package; the docker provider implements the operation and every other provider
// returns ErrUnsupported.

// Limits for module runs. They are the project run's limits restated for a table:
// the worker's results travel as one artifact under the same aggregate budget,
// so a request whose results could not fit is refused before dispatch (and, with
// the true output width known only to the module, by the worker before it runs a
// single row) rather than truncated.
const (
	MaxModuleRows        = 100_000
	MaxModuleRowWidth    = 64
	MaxModuleSteps       = 1_000_000
	MaxModuleResultBytes = 8 << 20 // the runner's aggregate artifact budget
	moduleResultHeader   = 20      // "PLSM", version, rows, width, params (uint32 each)
	moduleResultVersion  = 1
)

// moduleIDPattern is the whole grammar of a model id: a filename stem with no
// separator, so the provider's mapping to /models/<id>.so cannot leave /models.
var moduleIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// ModuleRequest runs Model once per row of Rows, each instance stepping from 0
// to EndTime with communication step Step. Every row has the same width, which
// must equal the model's own parameter count. Timeout is the total wall-clock
// budget; MinimumIsolation has the same semantics as Request.MinimumIsolation.
type ModuleRequest struct {
	Model            string
	Rows             [][]float64
	EndTime          float64
	Step             float64
	Timeout          time.Duration
	MinimumIsolation IsolationClass // Unknown = no request-specific floor
}

// ModuleRun is one row's result. Status is the number of steps the instance
// completed when >= 0, and the model's or worker's negative code when that row
// failed. Outputs holds Width values per completed step, step-major; nil when
// Status is not positive.
type ModuleRun struct {
	Status  int32
	Outputs []float64
}

// ModuleResult is the outcome of a module run. Runs has one entry per request
// row, in order, when Outcome is completed and is empty otherwise; Width is the
// number of outputs per step, read from the module. Outcome and Detail have the
// project run's meanings: setup_failed is the worker refusing the request (an
// unknown model, a malformed table), timed_out and protocol_error as for a
// project. Stdout is the worker's one summary line and Stderr its diagnostics,
// both bounded. Pre-dispatch failures and infrastructure faults are Go errors.
type ModuleResult struct {
	Runs      []ModuleRun
	Width     int
	Sandbox   string
	Isolation IsolationClass
	Outcome   ProjectOutcome
	Detail    string
	Stdout    string
	Stderr    string
	Duration  time.Duration
}

// MaxSteps is the worker's bound on steps per row for this envelope:
// floor(EndTime/Step) + 2, the same expression the worker evaluates.
func (r ModuleRequest) MaxSteps() int {
	return int(r.EndTime/r.Step) + 2
}

// RowWidth is the number of values per row (0 for an empty table).
func (r ModuleRequest) RowWidth() int {
	if len(r.Rows) == 0 {
		return 0
	}
	return len(r.Rows[0])
}

// ValidateModuleRequest is the pre-dispatch check every provider and the RPC
// layer apply. Beyond shape and finiteness it refuses a table whose results
// could not fit the result budget even at one output per step: the necessary
// condition the daemon can evaluate without the module. The worker applies the
// exact condition with the module's real width before running any row.
func ValidateModuleRequest(req ModuleRequest) error {
	if err := validateMinimumIsolation(req.MinimumIsolation); err != nil {
		return err
	}
	if !moduleIDPattern.MatchString(req.Model) {
		return fmt.Errorf("%w: model must match %s", ErrInvalidRequest, moduleIDPattern)
	}
	if len(req.Rows) == 0 {
		return fmt.Errorf("%w: at least one row is required", ErrInvalidRequest)
	}
	if len(req.Rows) > MaxModuleRows {
		return fmt.Errorf("%w: too many rows (max %d)", ErrInvalidRequest, MaxModuleRows)
	}
	width := len(req.Rows[0])
	if width == 0 || width > MaxModuleRowWidth {
		return fmt.Errorf("%w: rows must carry 1 to %d values", ErrInvalidRequest, MaxModuleRowWidth)
	}
	for i, row := range req.Rows {
		if len(row) != width {
			return fmt.Errorf("%w: row %d has %d values, row 0 has %d", ErrInvalidRequest, i, len(row), width)
		}
		for j, v := range row {
			if math.IsNaN(v) || math.IsInf(v, 0) {
				return fmt.Errorf("%w: row %d value %d is not finite", ErrInvalidRequest, i, j)
			}
		}
	}
	if !(req.EndTime > 0) || math.IsInf(req.EndTime, 0) {
		return fmt.Errorf("%w: end_time must be positive and finite", ErrInvalidRequest)
	}
	if !(req.Step > 0) || math.IsInf(req.Step, 0) {
		return fmt.Errorf("%w: step must be positive and finite", ErrInvalidRequest)
	}
	if req.EndTime/req.Step > MaxModuleSteps {
		return fmt.Errorf("%w: end_time/step exceeds %d steps", ErrInvalidRequest, MaxModuleSteps)
	}
	// Necessary condition at width 1; the worker checks the true width.
	worst := moduleResultHeader + int64(len(req.Rows))*(4+8*int64(req.MaxSteps()))
	if worst > MaxModuleResultBytes {
		return fmt.Errorf("%w: results could reach at least %d bytes for %d rows of up to %d steps, over the %d byte budget; send fewer rows or a shorter horizon",
			ErrInvalidRequest, worst, len(req.Rows), req.MaxSteps(), MaxModuleResultBytes)
	}
	return nil
}

// DecodeModuleResults parses the worker's versioned result record: a 20-byte
// header ("PLSM", uint32 version 1, uint32 rows, uint32 width, uint32 params),
// then per row an int32 status followed by status*width little-endian float64
// outputs when the status is positive. rows and params must match the request
// the worker ran (the row count and row width), so a record from some other run
// cannot be mistaken for this one's. Every length is checked against the bytes
// present before it is used: the record comes from inside the sandbox.
func DecodeModuleResults(b []byte, rows, params int) ([]ModuleRun, int, error) {
	if len(b) < moduleResultHeader {
		return nil, 0, fmt.Errorf("result record is %d bytes, shorter than its header", len(b))
	}
	if string(b[:4]) != "PLSM" {
		return nil, 0, fmt.Errorf("result record has magic %q, want \"PLSM\"", b[:4])
	}
	version := binary.LittleEndian.Uint32(b[4:8])
	gotRows := binary.LittleEndian.Uint32(b[8:12])
	width := binary.LittleEndian.Uint32(b[12:16])
	gotParams := binary.LittleEndian.Uint32(b[16:20])
	if version != moduleResultVersion {
		return nil, 0, fmt.Errorf("result record version %d, want %d", version, moduleResultVersion)
	}
	if int64(gotRows) != int64(rows) || int64(gotParams) != int64(params) {
		return nil, 0, fmt.Errorf("result record describes %d rows of %d params, the request had %d rows of %d", gotRows, gotParams, rows, params)
	}
	if width == 0 || width > 1<<16 {
		return nil, 0, fmt.Errorf("result record width %d is out of range", width)
	}
	runs := make([]ModuleRun, 0, rows)
	off := moduleResultHeader
	for i := 0; i < rows; i++ {
		if len(b)-off < 4 {
			return nil, 0, fmt.Errorf("result record ends inside row %d's status", i)
		}
		status := int32(binary.LittleEndian.Uint32(b[off:]))
		off += 4
		run := ModuleRun{Status: status}
		if status > 0 {
			count := int64(status) * int64(width)
			if count*8 > int64(len(b)-off) {
				return nil, 0, fmt.Errorf("result record ends inside row %d's outputs (%d steps of %d)", i, status, width)
			}
			run.Outputs = make([]float64, count)
			for k := range run.Outputs {
				run.Outputs[k] = math.Float64frombits(binary.LittleEndian.Uint64(b[off+8*k:]))
			}
			off += int(count) * 8
		}
		runs = append(runs, run)
	}
	if off != len(b) {
		return nil, 0, fmt.Errorf("result record has %d trailing bytes after row %d", len(b)-off, rows-1)
	}
	return runs, int(width), nil
}
