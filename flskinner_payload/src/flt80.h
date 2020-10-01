#pragma once

struct flt80 {
	char pad[ 10 ];
};

extern "C" void _cvt64to80( double* val, flt80 * out );