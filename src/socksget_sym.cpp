// Copyright The Phorepoc Authors
// SPDX-License-Identifier: Apache-2.0
//
// socksget on Symbian: a trace line on the serial port (RDebug) so a test host can read the fetched page without the disk.
#include <e32std.h>
#include <e32debug.h>

extern "C" void phe_trace(const char *line)
{
	TBuf8<200> b;
	b.Copy(TPtrC8((const TUint8 *)line).Left(190));
	for (TInt i = 0; i < b.Length(); ++i)
		if (b[i] < 32)
			b[i] = ' ';
	RDebug::Printf("[socksget] %S", &b);
}
