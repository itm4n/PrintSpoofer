

/* this ALWAYS GENERATED file contains the definitions for the interfaces */


 /* File created by MIDL compiler version 8.01.0622 */
/* at Tue Jan 19 04:14:07 2038
 */
/* Compiler settings for ms-rprn.idl:
    Oicf, W1, Zp8, env=Win64 (32b run), target_arch=AMD64 8.01.0622 
    protocol : all , ms_ext, c_ext, robust
    error checks: allocation ref bounds_check enum stub_data 
    VC __declspec() decoration level: 
         __declspec(uuid()), __declspec(selectany), __declspec(novtable)
         DECLSPEC_UUID(), MIDL_INTERFACE()
*/
/* @@MIDL_FILE_HEADING(  ) */



/* verify that the <rpcndr.h> version is high enough to compile this file*/
#ifndef __REQUIRED_RPCNDR_H_VERSION__
#define __REQUIRED_RPCNDR_H_VERSION__ 500
#endif

#include "rpc.h"
#include "rpcndr.h"

#ifndef __RPCNDR_H_VERSION__
#error this stub requires an updated version of <rpcndr.h>
#endif /* __RPCNDR_H_VERSION__ */


#ifndef __ms2Drprn_h_h__
#define __ms2Drprn_h_h__

#if defined(_MSC_VER) && (_MSC_VER >= 1020)
#pragma once
#endif

/* Forward Declarations */ 

/* header files for imported files */
#include "oaidl.h"

#ifdef __cplusplus
extern "C"{
#endif 


#ifndef __winspool_INTERFACE_DEFINED__
#define __winspool_INTERFACE_DEFINED__

/* interface winspool */
/* [unique][endpoint][ms_union][version][uuid] */ 

typedef struct _DEVMODE_CONTAINER
    {
    DWORD cbBuf;
    /* [unique][size_is] */ BYTE *pDevMode;
    } 	DEVMODE_CONTAINER;

typedef struct _RPC_V2_NOTIFY_OPTIONS_TYPE
    {
    unsigned short Type;
    unsigned short Reserved0;
    DWORD Reserved1;
    DWORD Reserved2;
    DWORD Count;
    /* [unique][size_is] */ unsigned short *pFields;
    } 	RPC_V2_NOTIFY_OPTIONS_TYPE;

typedef struct _RPC_V2_NOTIFY_OPTIONS
    {
    DWORD Version;
    DWORD Reserved;
    DWORD Count;
    /* [unique][size_is] */ RPC_V2_NOTIFY_OPTIONS_TYPE *pTypes;
    } 	RPC_V2_NOTIFY_OPTIONS;

typedef unsigned short LANGID;

typedef /* [context_handle] */ void *GDI_HANDLE;

typedef /* [context_handle] */ void *PRINTER_HANDLE;

typedef /* [handle] */ wchar_t *STRING_HANDLE;

DWORD RpcEnumPrinters( 
    /* [in] */ handle_t IDL_handle);

DWORD RpcOpenPrinter( 
    /* [unique][string][in] */ STRING_HANDLE pPrinterName,
    /* [out] */ PRINTER_HANDLE *pHandle,
    /* [unique][string][in] */ wchar_t *pDatatype,
    /* [in] */ DEVMODE_CONTAINER *pDevModeContainer,
    /* [in] */ DWORD AccessRequired);

DWORD RpcSetJob( 
    /* [in] */ handle_t IDL_handle);

DWORD RpcGetJob( 
    /* [in] */ handle_t IDL_handle);

DWORD RpcEnumJobs( 
    /* [in] */ handle_t IDL_handle);

DWORD RpcAddPrinter( 
    /* [in] */ handle_t IDL_handle);

DWORD RpcDeletePrinter( 
    /* [in] */ handle_t IDL_handle);

DWORD RpcSetPrinter( 
    /* [in] */ handle_t IDL_handle);

DWORD RpcGetPrinter( 
    /* [in] */ handle_t IDL_handle);

DWORD RpcAddPrinterDriver( 
    /* [in] */ handle_t IDL_handle);

DWORD RpcEnumPrinterDrivers( 
    /* [in] */ handle_t IDL_handle);

DWORD RpcGetPrinterDriver( 
    /* [in] */ handle_t IDL_handle);

DWORD RpcGetPrinterDriverDirectory( 
    /* [in] */ handle_t IDL_handle);

DWORD RpcDeletePrinterDriver( 
    /* [in] */ handle_t IDL_handle);

DWORD RpcAddPrintProcessor( 
    /* [in] */ handle_t IDL_handle);

DWORD RpcEnumPrintProcessors( 
    /* [in] */ handle_t IDL_handle);

DWORD RpcGetPrintProcessorDirectory( 
    /* [in] */ handle_t IDL_handle);

DWORD RpcStartDocPrinter( 
    /* [in] */ handle_t IDL_handle);

DWORD RpcStartPagePrinter( 
    /* [in] */ handle_t IDL_handle);

DWORD RpcWritePrinter( 
    /* [in] */ handle_t IDL_handle);

DWORD RpcEndPagePrinter( 
    /* [in] */ handle_t IDL_handle);

DWORD RpcAbortPrinter( 
    /* [in] */ handle_t IDL_handle);

DWORD RpcReadPrinter( 
    /* [in] */ handle_t IDL_handle);

DWORD RpcEndDocPrinter( 
    /* [in] */ handle_t IDL_handle);

DWORD RpcAddJob( 
    /* [in] */ handle_t IDL_handle);

DWORD RpcScheduleJob( 
    /* [in] */ handle_t IDL_handle);

DWORD RpcGetPrinterData( 
    /* [in] */ handle_t IDL_handle);

DWORD RpcSetPrinterData( 
    /* [in] */ handle_t IDL_handle);

DWORD RpcWaitForPrinterChange( 
    /* [in] */ handle_t IDL_handle);

DWORD RpcClosePrinter( 
    /* [out][in] */ PRINTER_HANDLE *phPrinter);

DWORD RpcAddForm( 
    /* [in] */ handle_t IDL_handle);

DWORD RpcDeleteForm( 
    /* [in] */ handle_t IDL_handle);

DWORD RpcGetForm( 
    /* [in] */ handle_t IDL_handle);

DWORD RpcSetForm( 
    /* [in] */ handle_t IDL_handle);

DWORD RpcEnumForms( 
    /* [in] */ handle_t IDL_handle);

DWORD RpcEnumPorts( 
    /* [in] */ handle_t IDL_handle);

DWORD RpcEnumMonitors( 
    /* [in] */ handle_t IDL_handle);

void Opnum37NotUsedOnWire( 
    /* [in] */ handle_t IDL_handle);

void Opnum38NotUsedOnWire( 
    /* [in] */ handle_t IDL_handle);

DWORD RpcDeletePort( 
    /* [in] */ handle_t IDL_handle);

DWORD RpcCreatePrinterIC( 
    /* [in] */ handle_t IDL_handle);

DWORD RpcPlayGdiScriptOnPrinterIC( 
    /* [in] */ handle_t IDL_handle);

DWORD RpcDeletePrinterIC( 
    /* [in] */ handle_t IDL_handle);

void Opnum43NotUsedOnWire( 
    /* [in] */ handle_t IDL_handle);

void Opnum44NotUsedOnWire( 
    /* [in] */ handle_t IDL_handle);

void Opnum45NotUsedOnWire( 
    /* [in] */ handle_t IDL_handle);

DWORD RpcAddMonitor( 
    /* [in] */ handle_t IDL_handle);

DWORD RpcDeleteMonitor( 
    /* [in] */ handle_t IDL_handle);

DWORD RpcDeletePrintProcessor( 
    /* [in] */ handle_t IDL_handle);

void Opnum49NotUsedOnWire( 
    /* [in] */ handle_t IDL_handle);

void Opnum50NotUsedOnWire( 
    /* [in] */ handle_t IDL_handle);

DWORD RpcEnumPrintProcessorDatatypes( 
    /* [in] */ handle_t IDL_handle);

DWORD RpcResetPrinter( 
    /* [in] */ handle_t IDL_handle);

DWORD RpcGetPrinterDriver2( 
    /* [in] */ handle_t IDL_handle);

void Opnum54NotUsedOnWire( 
    /* [in] */ handle_t IDL_handle);

void Opnum55NotUsedOnWire( 
    /* [in] */ handle_t IDL_handle);

DWORD RpcFindClosePrinterChangeNotification( 
    /* [in] */ handle_t IDL_handle);

void Opnum57NotUsedOnWire( 
    /* [in] */ handle_t IDL_handle);

DWORD RpcReplyOpenPrinter( 
    /* [in] */ handle_t IDL_handle);

DWORD RpcRouterReplyPrinter( 
    /* [in] */ handle_t IDL_handle);

DWORD RpcReplyClosePrinter( 
    /* [in] */ handle_t IDL_handle);

DWORD RpcAddPortEx( 
    /* [in] */ handle_t IDL_handle);

DWORD RpcRemoteFindFirstPrinterChangeNotification( 
    /* [in] */ handle_t IDL_handle);

void Opnum63NotUsedOnWire( 
    /* [in] */ handle_t IDL_handle);

void Opnum64NotUsedOnWire( 
    /* [in] */ handle_t IDL_handle);

DWORD RpcRemoteFindFirstPrinterChangeNotificationEx( 
    /* [in] */ PRINTER_HANDLE hPrinter,
    /* [in] */ DWORD fdwFlags,
    /* [in] */ DWORD fdwOptions,
    /* [unique][string][in] */ wchar_t *pszLocalMachine,
    /* [in] */ DWORD dwPrinterLocal,
    /* [unique][in] */ RPC_V2_NOTIFY_OPTIONS *pOptions);



extern RPC_IF_HANDLE winspool_v1_0_c_ifspec;
extern RPC_IF_HANDLE winspool_v1_0_s_ifspec;
#endif /* __winspool_INTERFACE_DEFINED__ */

/* Additional Prototypes for ALL interfaces */

handle_t __RPC_USER STRING_HANDLE_bind ( STRING_HANDLE );
void     __RPC_USER STRING_HANDLE_unbind( STRING_HANDLE,  handle_t );

void __RPC_USER PRINTER_HANDLE_rundown( PRINTER_HANDLE );

/* end of Additional Prototypes */

#ifdef __cplusplus
}
#endif

#endif


