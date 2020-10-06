#pragma warning(disable:4201)  //nonstandard extension used : nameless struct/union
#include <ntifs.h>
#include <ndis.h>
#include <Fltkernel.h>
//#include <ntddk.h>
#include <wdm.h>
#include <filteruser.h>
#include <stdio.h>
#include <stdlib.h>
#include "flt_dbg.h"
#include "filter.h"
#include "Packet.h"