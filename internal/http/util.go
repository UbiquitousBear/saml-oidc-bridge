package http

func hasAnyGroup(user map[string]struct{}, want []string) bool {
	if len(want) == 0 {
		return false
	}
	for _, g := range want {
		if _, ok := user[g]; ok {
			return true
		}
	}
	return false
}

func toSet(ss []string) map[string]struct{} {
	m := make(map[string]struct{}, len(ss))
	for _, s := range ss {
		m[s] = struct{}{}
	}
	return m
}
