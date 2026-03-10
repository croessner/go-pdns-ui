package domain

type ZoneKind string

const (
	ZoneForward   ZoneKind = "forward"
	ZoneReverseV4 ZoneKind = "reverse-v4"
	ZoneReverseV6 ZoneKind = "reverse-v6"
)

func (k ZoneKind) Valid() bool {
	switch k {
	case ZoneForward, ZoneReverseV4, ZoneReverseV6:
		return true
	default:
		return false
	}
}

type Record struct {
	Name     string
	Type     string
	TTL      uint32
	Content  string
	Disabled bool
}

type Zone struct {
	Name          string
	Kind          ZoneKind
	DNSSECEnabled bool
	Records       []Record
}

type ZoneTemplate struct {
	Name    string
	Kind    ZoneKind
	Records []Record
}
