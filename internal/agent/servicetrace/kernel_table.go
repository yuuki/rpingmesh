package servicetrace

// applyKernel handles self-contained modify events: kernel QPs do not have
// uverbs creates, handles or context-close events. Caller holds t.mu.
func (t *Table) applyKernel(ev Event) bool {
	if ev.Context == 0 || !IsConnectedType(ev.QPType) {
		t.counters.Ignored++
		return false
	}
	previous, exists := t.kernelQPs[ev.Context]
	switch {
	case ev.Kind == KindQPDestroy, ev.IsReset(),
		ev.Kind == KindQPModify && ev.AttrMask&AttrMaskState != 0 && ev.QPState == QPStateErr:
		delete(t.kernelQPs, ev.Context)
		if ev.Kind == KindQPDestroy {
			t.counters.Destroys++
		} else {
			t.counters.Resets++
		}
		return exists
	case ev.IsConnect():
		if ev.DGID == ([16]byte{}) || ev.DestQPNum == 0 || ev.DestPortNum == 0 ||
			ev.AttrMask&AttrMaskDestQPN == 0 || ev.IsGlobal&1 == 0 {
			t.counters.Ignored++
			return false
		}
		c := newConnection(&uverbsContext{dev: ev.Dev}, &qpEntry{qpn: ev.QPNum, qpType: ev.QPType}, ev)
		c.Kernel = true
		t.kernelQPs[ev.Context] = *c
		t.counters.Connects++
		return !exists || previous != *c
	}
	t.counters.Ignored++
	return false
}

// A successful inventory bounds missed kernel destroy/reset events without
// depending on the lifetime of the worker that happened to call ib_modify_qp.
func (t *Table) reconcileKernelQPs(resources []QPResource) bool {
	live := make(map[qpResourceKey]QPResource)
	for _, qp := range resources {
		if qp.Kernel && (qp.QPState == QPStateRTR || qp.QPState == QPStateRTS) {
			live[qpResourceKey{qp.Dev, qp.LocalQPN}] = qp
		}
	}
	changed := false
	for ptr, c := range t.kernelQPs {
		qp, ok := live[qpResourceKey{c.Dev, c.LocalQPN}]
		if !ok || qp.QPType != c.QPType || (qp.RemoteQPN != 0 && qp.RemoteQPN != c.RemoteQPN) {
			delete(t.kernelQPs, ptr)
			changed = true
		}
	}
	return changed
}
