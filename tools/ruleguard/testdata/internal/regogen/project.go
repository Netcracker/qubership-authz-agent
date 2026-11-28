package regogen

// Record stands in for the record of an operand.
type Record struct {
	State string
	Value any
}

func record(state string) Record {
	r := Record{State: state}
	r.Value = nil
	return r
}
