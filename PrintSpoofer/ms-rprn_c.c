

/* this ALWAYS GENERATED file contains the RPC client stubs */


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

#if defined(_M_AMD64)


#if _MSC_VER >= 1200
#pragma warning(push)
#endif

#pragma warning( disable: 4211 )  /* redefine extern to static */
#pragma warning( disable: 4232 )  /* dllimport identity*/
#pragma warning( disable: 4024 )  /* array to pointer mapping*/

#include <string.h>

#include "ms-rprn_h.h"

#define TYPE_FORMAT_STRING_SIZE   135                               
#define PROC_FORMAT_STRING_SIZE   2383                              
#define EXPR_FORMAT_STRING_SIZE   1                                 
#define TRANSMIT_AS_TABLE_SIZE    0            
#define WIRE_MARSHAL_TABLE_SIZE   0            

typedef struct _ms2Drprn_MIDL_TYPE_FORMAT_STRING
    {
    short          Pad;
    unsigned char  Format[ TYPE_FORMAT_STRING_SIZE ];
    } ms2Drprn_MIDL_TYPE_FORMAT_STRING;

typedef struct _ms2Drprn_MIDL_PROC_FORMAT_STRING
    {
    short          Pad;
    unsigned char  Format[ PROC_FORMAT_STRING_SIZE ];
    } ms2Drprn_MIDL_PROC_FORMAT_STRING;

typedef struct _ms2Drprn_MIDL_EXPR_FORMAT_STRING
    {
    long          Pad;
    unsigned char  Format[ EXPR_FORMAT_STRING_SIZE ];
    } ms2Drprn_MIDL_EXPR_FORMAT_STRING;


static const RPC_SYNTAX_IDENTIFIER  _RpcTransferSyntax = 
{{0x8A885D04,0x1CEB,0x11C9,{0x9F,0xE8,0x08,0x00,0x2B,0x10,0x48,0x60}},{2,0}};

static const RPC_SYNTAX_IDENTIFIER  _NDR64_RpcTransferSyntax = 
{{0x71710533,0xbeba,0x4937,{0x83,0x19,0xb5,0xdb,0xef,0x9c,0xcc,0x36}},{1,0}};



extern const ms2Drprn_MIDL_TYPE_FORMAT_STRING ms2Drprn__MIDL_TypeFormatString;
extern const ms2Drprn_MIDL_PROC_FORMAT_STRING ms2Drprn__MIDL_ProcFormatString;
extern const ms2Drprn_MIDL_EXPR_FORMAT_STRING ms2Drprn__MIDL_ExprFormatString;

#define GENERIC_BINDING_TABLE_SIZE   1            


/* Standard interface: winspool, ver. 1.0,
   GUID={0x12345678,0x1234,0xABCD,{0xEF,0x00,0x01,0x23,0x45,0x67,0x89,0xAB}} */

 extern const MIDL_STUBLESS_PROXY_INFO winspool_ProxyInfo;

static const RPC_PROTSEQ_ENDPOINT __RpcProtseqEndpoint[] = 
    {
    {(unsigned char *) "ncacn_np", (unsigned char *) "\\pipe\\spoolss"}
    };


static const RPC_CLIENT_INTERFACE winspool___RpcClientInterface =
    {
    sizeof(RPC_CLIENT_INTERFACE),
    {{0x12345678,0x1234,0xABCD,{0xEF,0x00,0x01,0x23,0x45,0x67,0x89,0xAB}},{1,0}},
    {{0x8A885D04,0x1CEB,0x11C9,{0x9F,0xE8,0x08,0x00,0x2B,0x10,0x48,0x60}},{2,0}},
    0,
    1,
    (RPC_PROTSEQ_ENDPOINT *)__RpcProtseqEndpoint,
    0,
    &winspool_ProxyInfo,
    0x02000000
    };
RPC_IF_HANDLE winspool_v1_0_c_ifspec = (RPC_IF_HANDLE)& winspool___RpcClientInterface;

extern const MIDL_STUB_DESC winspool_StubDesc;

static RPC_BINDING_HANDLE winspool__MIDL_AutoBindHandle;


DWORD RpcEnumPrinters( 
    /* [in] */ handle_t IDL_handle)
{

    CLIENT_CALL_RETURN _RetVal;

    _RetVal = NdrClientCall3(
                  ( PMIDL_STUBLESS_PROXY_INFO  )&winspool_ProxyInfo,
                  0,
                  0,
                  IDL_handle);
    return ( DWORD  )_RetVal.Simple;
    
}


DWORD RpcOpenPrinter( 
    /* [unique][string][in] */ STRING_HANDLE pPrinterName,
    /* [out] */ PRINTER_HANDLE *pHandle,
    /* [unique][string][in] */ wchar_t *pDatatype,
    /* [in] */ DEVMODE_CONTAINER *pDevModeContainer,
    /* [in] */ DWORD AccessRequired)
{

    CLIENT_CALL_RETURN _RetVal;

    _RetVal = NdrClientCall3(
                  ( PMIDL_STUBLESS_PROXY_INFO  )&winspool_ProxyInfo,
                  1,
                  0,
                  pPrinterName,
                  pHandle,
                  pDatatype,
                  pDevModeContainer,
                  AccessRequired);
    return ( DWORD  )_RetVal.Simple;
    
}


DWORD RpcSetJob( 
    /* [in] */ handle_t IDL_handle)
{

    CLIENT_CALL_RETURN _RetVal;

    _RetVal = NdrClientCall3(
                  ( PMIDL_STUBLESS_PROXY_INFO  )&winspool_ProxyInfo,
                  2,
                  0,
                  IDL_handle);
    return ( DWORD  )_RetVal.Simple;
    
}


DWORD RpcGetJob( 
    /* [in] */ handle_t IDL_handle)
{

    CLIENT_CALL_RETURN _RetVal;

    _RetVal = NdrClientCall3(
                  ( PMIDL_STUBLESS_PROXY_INFO  )&winspool_ProxyInfo,
                  3,
                  0,
                  IDL_handle);
    return ( DWORD  )_RetVal.Simple;
    
}


DWORD RpcEnumJobs( 
    /* [in] */ handle_t IDL_handle)
{

    CLIENT_CALL_RETURN _RetVal;

    _RetVal = NdrClientCall3(
                  ( PMIDL_STUBLESS_PROXY_INFO  )&winspool_ProxyInfo,
                  4,
                  0,
                  IDL_handle);
    return ( DWORD  )_RetVal.Simple;
    
}


DWORD RpcAddPrinter( 
    /* [in] */ handle_t IDL_handle)
{

    CLIENT_CALL_RETURN _RetVal;

    _RetVal = NdrClientCall3(
                  ( PMIDL_STUBLESS_PROXY_INFO  )&winspool_ProxyInfo,
                  5,
                  0,
                  IDL_handle);
    return ( DWORD  )_RetVal.Simple;
    
}


DWORD RpcDeletePrinter( 
    /* [in] */ handle_t IDL_handle)
{

    CLIENT_CALL_RETURN _RetVal;

    _RetVal = NdrClientCall3(
                  ( PMIDL_STUBLESS_PROXY_INFO  )&winspool_ProxyInfo,
                  6,
                  0,
                  IDL_handle);
    return ( DWORD  )_RetVal.Simple;
    
}


DWORD RpcSetPrinter( 
    /* [in] */ handle_t IDL_handle)
{

    CLIENT_CALL_RETURN _RetVal;

    _RetVal = NdrClientCall3(
                  ( PMIDL_STUBLESS_PROXY_INFO  )&winspool_ProxyInfo,
                  7,
                  0,
                  IDL_handle);
    return ( DWORD  )_RetVal.Simple;
    
}


DWORD RpcGetPrinter( 
    /* [in] */ handle_t IDL_handle)
{

    CLIENT_CALL_RETURN _RetVal;

    _RetVal = NdrClientCall3(
                  ( PMIDL_STUBLESS_PROXY_INFO  )&winspool_ProxyInfo,
                  8,
                  0,
                  IDL_handle);
    return ( DWORD  )_RetVal.Simple;
    
}


DWORD RpcAddPrinterDriver( 
    /* [in] */ handle_t IDL_handle)
{

    CLIENT_CALL_RETURN _RetVal;

    _RetVal = NdrClientCall3(
                  ( PMIDL_STUBLESS_PROXY_INFO  )&winspool_ProxyInfo,
                  9,
                  0,
                  IDL_handle);
    return ( DWORD  )_RetVal.Simple;
    
}


DWORD RpcEnumPrinterDrivers( 
    /* [in] */ handle_t IDL_handle)
{

    CLIENT_CALL_RETURN _RetVal;

    _RetVal = NdrClientCall3(
                  ( PMIDL_STUBLESS_PROXY_INFO  )&winspool_ProxyInfo,
                  10,
                  0,
                  IDL_handle);
    return ( DWORD  )_RetVal.Simple;
    
}


DWORD RpcGetPrinterDriver( 
    /* [in] */ handle_t IDL_handle)
{

    CLIENT_CALL_RETURN _RetVal;

    _RetVal = NdrClientCall3(
                  ( PMIDL_STUBLESS_PROXY_INFO  )&winspool_ProxyInfo,
                  11,
                  0,
                  IDL_handle);
    return ( DWORD  )_RetVal.Simple;
    
}


DWORD RpcGetPrinterDriverDirectory( 
    /* [in] */ handle_t IDL_handle)
{

    CLIENT_CALL_RETURN _RetVal;

    _RetVal = NdrClientCall3(
                  ( PMIDL_STUBLESS_PROXY_INFO  )&winspool_ProxyInfo,
                  12,
                  0,
                  IDL_handle);
    return ( DWORD  )_RetVal.Simple;
    
}


DWORD RpcDeletePrinterDriver( 
    /* [in] */ handle_t IDL_handle)
{

    CLIENT_CALL_RETURN _RetVal;

    _RetVal = NdrClientCall3(
                  ( PMIDL_STUBLESS_PROXY_INFO  )&winspool_ProxyInfo,
                  13,
                  0,
                  IDL_handle);
    return ( DWORD  )_RetVal.Simple;
    
}


DWORD RpcAddPrintProcessor( 
    /* [in] */ handle_t IDL_handle)
{

    CLIENT_CALL_RETURN _RetVal;

    _RetVal = NdrClientCall3(
                  ( PMIDL_STUBLESS_PROXY_INFO  )&winspool_ProxyInfo,
                  14,
                  0,
                  IDL_handle);
    return ( DWORD  )_RetVal.Simple;
    
}


DWORD RpcEnumPrintProcessors( 
    /* [in] */ handle_t IDL_handle)
{

    CLIENT_CALL_RETURN _RetVal;

    _RetVal = NdrClientCall3(
                  ( PMIDL_STUBLESS_PROXY_INFO  )&winspool_ProxyInfo,
                  15,
                  0,
                  IDL_handle);
    return ( DWORD  )_RetVal.Simple;
    
}


DWORD RpcGetPrintProcessorDirectory( 
    /* [in] */ handle_t IDL_handle)
{

    CLIENT_CALL_RETURN _RetVal;

    _RetVal = NdrClientCall3(
                  ( PMIDL_STUBLESS_PROXY_INFO  )&winspool_ProxyInfo,
                  16,
                  0,
                  IDL_handle);
    return ( DWORD  )_RetVal.Simple;
    
}


DWORD RpcStartDocPrinter( 
    /* [in] */ handle_t IDL_handle)
{

    CLIENT_CALL_RETURN _RetVal;

    _RetVal = NdrClientCall3(
                  ( PMIDL_STUBLESS_PROXY_INFO  )&winspool_ProxyInfo,
                  17,
                  0,
                  IDL_handle);
    return ( DWORD  )_RetVal.Simple;
    
}


DWORD RpcStartPagePrinter( 
    /* [in] */ handle_t IDL_handle)
{

    CLIENT_CALL_RETURN _RetVal;

    _RetVal = NdrClientCall3(
                  ( PMIDL_STUBLESS_PROXY_INFO  )&winspool_ProxyInfo,
                  18,
                  0,
                  IDL_handle);
    return ( DWORD  )_RetVal.Simple;
    
}


DWORD RpcWritePrinter( 
    /* [in] */ handle_t IDL_handle)
{

    CLIENT_CALL_RETURN _RetVal;

    _RetVal = NdrClientCall3(
                  ( PMIDL_STUBLESS_PROXY_INFO  )&winspool_ProxyInfo,
                  19,
                  0,
                  IDL_handle);
    return ( DWORD  )_RetVal.Simple;
    
}


DWORD RpcEndPagePrinter( 
    /* [in] */ handle_t IDL_handle)
{

    CLIENT_CALL_RETURN _RetVal;

    _RetVal = NdrClientCall3(
                  ( PMIDL_STUBLESS_PROXY_INFO  )&winspool_ProxyInfo,
                  20,
                  0,
                  IDL_handle);
    return ( DWORD  )_RetVal.Simple;
    
}


DWORD RpcAbortPrinter( 
    /* [in] */ handle_t IDL_handle)
{

    CLIENT_CALL_RETURN _RetVal;

    _RetVal = NdrClientCall3(
                  ( PMIDL_STUBLESS_PROXY_INFO  )&winspool_ProxyInfo,
                  21,
                  0,
                  IDL_handle);
    return ( DWORD  )_RetVal.Simple;
    
}


DWORD RpcReadPrinter( 
    /* [in] */ handle_t IDL_handle)
{

    CLIENT_CALL_RETURN _RetVal;

    _RetVal = NdrClientCall3(
                  ( PMIDL_STUBLESS_PROXY_INFO  )&winspool_ProxyInfo,
                  22,
                  0,
                  IDL_handle);
    return ( DWORD  )_RetVal.Simple;
    
}


DWORD RpcEndDocPrinter( 
    /* [in] */ handle_t IDL_handle)
{

    CLIENT_CALL_RETURN _RetVal;

    _RetVal = NdrClientCall3(
                  ( PMIDL_STUBLESS_PROXY_INFO  )&winspool_ProxyInfo,
                  23,
                  0,
                  IDL_handle);
    return ( DWORD  )_RetVal.Simple;
    
}


DWORD RpcAddJob( 
    /* [in] */ handle_t IDL_handle)
{

    CLIENT_CALL_RETURN _RetVal;

    _RetVal = NdrClientCall3(
                  ( PMIDL_STUBLESS_PROXY_INFO  )&winspool_ProxyInfo,
                  24,
                  0,
                  IDL_handle);
    return ( DWORD  )_RetVal.Simple;
    
}


DWORD RpcScheduleJob( 
    /* [in] */ handle_t IDL_handle)
{

    CLIENT_CALL_RETURN _RetVal;

    _RetVal = NdrClientCall3(
                  ( PMIDL_STUBLESS_PROXY_INFO  )&winspool_ProxyInfo,
                  25,
                  0,
                  IDL_handle);
    return ( DWORD  )_RetVal.Simple;
    
}


DWORD RpcGetPrinterData( 
    /* [in] */ handle_t IDL_handle)
{

    CLIENT_CALL_RETURN _RetVal;

    _RetVal = NdrClientCall3(
                  ( PMIDL_STUBLESS_PROXY_INFO  )&winspool_ProxyInfo,
                  26,
                  0,
                  IDL_handle);
    return ( DWORD  )_RetVal.Simple;
    
}


DWORD RpcSetPrinterData( 
    /* [in] */ handle_t IDL_handle)
{

    CLIENT_CALL_RETURN _RetVal;

    _RetVal = NdrClientCall3(
                  ( PMIDL_STUBLESS_PROXY_INFO  )&winspool_ProxyInfo,
                  27,
                  0,
                  IDL_handle);
    return ( DWORD  )_RetVal.Simple;
    
}


DWORD RpcWaitForPrinterChange( 
    /* [in] */ handle_t IDL_handle)
{

    CLIENT_CALL_RETURN _RetVal;

    _RetVal = NdrClientCall3(
                  ( PMIDL_STUBLESS_PROXY_INFO  )&winspool_ProxyInfo,
                  28,
                  0,
                  IDL_handle);
    return ( DWORD  )_RetVal.Simple;
    
}


DWORD RpcClosePrinter( 
    /* [out][in] */ PRINTER_HANDLE *phPrinter)
{

    CLIENT_CALL_RETURN _RetVal;

    _RetVal = NdrClientCall3(
                  ( PMIDL_STUBLESS_PROXY_INFO  )&winspool_ProxyInfo,
                  29,
                  0,
                  phPrinter);
    return ( DWORD  )_RetVal.Simple;
    
}


DWORD RpcAddForm( 
    /* [in] */ handle_t IDL_handle)
{

    CLIENT_CALL_RETURN _RetVal;

    _RetVal = NdrClientCall3(
                  ( PMIDL_STUBLESS_PROXY_INFO  )&winspool_ProxyInfo,
                  30,
                  0,
                  IDL_handle);
    return ( DWORD  )_RetVal.Simple;
    
}


DWORD RpcDeleteForm( 
    /* [in] */ handle_t IDL_handle)
{

    CLIENT_CALL_RETURN _RetVal;

    _RetVal = NdrClientCall3(
                  ( PMIDL_STUBLESS_PROXY_INFO  )&winspool_ProxyInfo,
                  31,
                  0,
                  IDL_handle);
    return ( DWORD  )_RetVal.Simple;
    
}


DWORD RpcGetForm( 
    /* [in] */ handle_t IDL_handle)
{

    CLIENT_CALL_RETURN _RetVal;

    _RetVal = NdrClientCall3(
                  ( PMIDL_STUBLESS_PROXY_INFO  )&winspool_ProxyInfo,
                  32,
                  0,
                  IDL_handle);
    return ( DWORD  )_RetVal.Simple;
    
}


DWORD RpcSetForm( 
    /* [in] */ handle_t IDL_handle)
{

    CLIENT_CALL_RETURN _RetVal;

    _RetVal = NdrClientCall3(
                  ( PMIDL_STUBLESS_PROXY_INFO  )&winspool_ProxyInfo,
                  33,
                  0,
                  IDL_handle);
    return ( DWORD  )_RetVal.Simple;
    
}


DWORD RpcEnumForms( 
    /* [in] */ handle_t IDL_handle)
{

    CLIENT_CALL_RETURN _RetVal;

    _RetVal = NdrClientCall3(
                  ( PMIDL_STUBLESS_PROXY_INFO  )&winspool_ProxyInfo,
                  34,
                  0,
                  IDL_handle);
    return ( DWORD  )_RetVal.Simple;
    
}


DWORD RpcEnumPorts( 
    /* [in] */ handle_t IDL_handle)
{

    CLIENT_CALL_RETURN _RetVal;

    _RetVal = NdrClientCall3(
                  ( PMIDL_STUBLESS_PROXY_INFO  )&winspool_ProxyInfo,
                  35,
                  0,
                  IDL_handle);
    return ( DWORD  )_RetVal.Simple;
    
}


DWORD RpcEnumMonitors( 
    /* [in] */ handle_t IDL_handle)
{

    CLIENT_CALL_RETURN _RetVal;

    _RetVal = NdrClientCall3(
                  ( PMIDL_STUBLESS_PROXY_INFO  )&winspool_ProxyInfo,
                  36,
                  0,
                  IDL_handle);
    return ( DWORD  )_RetVal.Simple;
    
}


void Opnum37NotUsedOnWire( 
    /* [in] */ handle_t IDL_handle)
{

    NdrClientCall3(
                  ( PMIDL_STUBLESS_PROXY_INFO  )&winspool_ProxyInfo,
                  37,
                  0,
                  IDL_handle);
    
}


void Opnum38NotUsedOnWire( 
    /* [in] */ handle_t IDL_handle)
{

    NdrClientCall3(
                  ( PMIDL_STUBLESS_PROXY_INFO  )&winspool_ProxyInfo,
                  38,
                  0,
                  IDL_handle);
    
}


DWORD RpcDeletePort( 
    /* [in] */ handle_t IDL_handle)
{

    CLIENT_CALL_RETURN _RetVal;

    _RetVal = NdrClientCall3(
                  ( PMIDL_STUBLESS_PROXY_INFO  )&winspool_ProxyInfo,
                  39,
                  0,
                  IDL_handle);
    return ( DWORD  )_RetVal.Simple;
    
}


DWORD RpcCreatePrinterIC( 
    /* [in] */ handle_t IDL_handle)
{

    CLIENT_CALL_RETURN _RetVal;

    _RetVal = NdrClientCall3(
                  ( PMIDL_STUBLESS_PROXY_INFO  )&winspool_ProxyInfo,
                  40,
                  0,
                  IDL_handle);
    return ( DWORD  )_RetVal.Simple;
    
}


DWORD RpcPlayGdiScriptOnPrinterIC( 
    /* [in] */ handle_t IDL_handle)
{

    CLIENT_CALL_RETURN _RetVal;

    _RetVal = NdrClientCall3(
                  ( PMIDL_STUBLESS_PROXY_INFO  )&winspool_ProxyInfo,
                  41,
                  0,
                  IDL_handle);
    return ( DWORD  )_RetVal.Simple;
    
}


DWORD RpcDeletePrinterIC( 
    /* [in] */ handle_t IDL_handle)
{

    CLIENT_CALL_RETURN _RetVal;

    _RetVal = NdrClientCall3(
                  ( PMIDL_STUBLESS_PROXY_INFO  )&winspool_ProxyInfo,
                  42,
                  0,
                  IDL_handle);
    return ( DWORD  )_RetVal.Simple;
    
}


void Opnum43NotUsedOnWire( 
    /* [in] */ handle_t IDL_handle)
{

    NdrClientCall3(
                  ( PMIDL_STUBLESS_PROXY_INFO  )&winspool_ProxyInfo,
                  43,
                  0,
                  IDL_handle);
    
}


void Opnum44NotUsedOnWire( 
    /* [in] */ handle_t IDL_handle)
{

    NdrClientCall3(
                  ( PMIDL_STUBLESS_PROXY_INFO  )&winspool_ProxyInfo,
                  44,
                  0,
                  IDL_handle);
    
}


void Opnum45NotUsedOnWire( 
    /* [in] */ handle_t IDL_handle)
{

    NdrClientCall3(
                  ( PMIDL_STUBLESS_PROXY_INFO  )&winspool_ProxyInfo,
                  45,
                  0,
                  IDL_handle);
    
}


DWORD RpcAddMonitor( 
    /* [in] */ handle_t IDL_handle)
{

    CLIENT_CALL_RETURN _RetVal;

    _RetVal = NdrClientCall3(
                  ( PMIDL_STUBLESS_PROXY_INFO  )&winspool_ProxyInfo,
                  46,
                  0,
                  IDL_handle);
    return ( DWORD  )_RetVal.Simple;
    
}


DWORD RpcDeleteMonitor( 
    /* [in] */ handle_t IDL_handle)
{

    CLIENT_CALL_RETURN _RetVal;

    _RetVal = NdrClientCall3(
                  ( PMIDL_STUBLESS_PROXY_INFO  )&winspool_ProxyInfo,
                  47,
                  0,
                  IDL_handle);
    return ( DWORD  )_RetVal.Simple;
    
}


DWORD RpcDeletePrintProcessor( 
    /* [in] */ handle_t IDL_handle)
{

    CLIENT_CALL_RETURN _RetVal;

    _RetVal = NdrClientCall3(
                  ( PMIDL_STUBLESS_PROXY_INFO  )&winspool_ProxyInfo,
                  48,
                  0,
                  IDL_handle);
    return ( DWORD  )_RetVal.Simple;
    
}


void Opnum49NotUsedOnWire( 
    /* [in] */ handle_t IDL_handle)
{

    NdrClientCall3(
                  ( PMIDL_STUBLESS_PROXY_INFO  )&winspool_ProxyInfo,
                  49,
                  0,
                  IDL_handle);
    
}


void Opnum50NotUsedOnWire( 
    /* [in] */ handle_t IDL_handle)
{

    NdrClientCall3(
                  ( PMIDL_STUBLESS_PROXY_INFO  )&winspool_ProxyInfo,
                  50,
                  0,
                  IDL_handle);
    
}


DWORD RpcEnumPrintProcessorDatatypes( 
    /* [in] */ handle_t IDL_handle)
{

    CLIENT_CALL_RETURN _RetVal;

    _RetVal = NdrClientCall3(
                  ( PMIDL_STUBLESS_PROXY_INFO  )&winspool_ProxyInfo,
                  51,
                  0,
                  IDL_handle);
    return ( DWORD  )_RetVal.Simple;
    
}


DWORD RpcResetPrinter( 
    /* [in] */ handle_t IDL_handle)
{

    CLIENT_CALL_RETURN _RetVal;

    _RetVal = NdrClientCall3(
                  ( PMIDL_STUBLESS_PROXY_INFO  )&winspool_ProxyInfo,
                  52,
                  0,
                  IDL_handle);
    return ( DWORD  )_RetVal.Simple;
    
}


DWORD RpcGetPrinterDriver2( 
    /* [in] */ handle_t IDL_handle)
{

    CLIENT_CALL_RETURN _RetVal;

    _RetVal = NdrClientCall3(
                  ( PMIDL_STUBLESS_PROXY_INFO  )&winspool_ProxyInfo,
                  53,
                  0,
                  IDL_handle);
    return ( DWORD  )_RetVal.Simple;
    
}


void Opnum54NotUsedOnWire( 
    /* [in] */ handle_t IDL_handle)
{

    NdrClientCall3(
                  ( PMIDL_STUBLESS_PROXY_INFO  )&winspool_ProxyInfo,
                  54,
                  0,
                  IDL_handle);
    
}


void Opnum55NotUsedOnWire( 
    /* [in] */ handle_t IDL_handle)
{

    NdrClientCall3(
                  ( PMIDL_STUBLESS_PROXY_INFO  )&winspool_ProxyInfo,
                  55,
                  0,
                  IDL_handle);
    
}


DWORD RpcFindClosePrinterChangeNotification( 
    /* [in] */ handle_t IDL_handle)
{

    CLIENT_CALL_RETURN _RetVal;

    _RetVal = NdrClientCall3(
                  ( PMIDL_STUBLESS_PROXY_INFO  )&winspool_ProxyInfo,
                  56,
                  0,
                  IDL_handle);
    return ( DWORD  )_RetVal.Simple;
    
}


void Opnum57NotUsedOnWire( 
    /* [in] */ handle_t IDL_handle)
{

    NdrClientCall3(
                  ( PMIDL_STUBLESS_PROXY_INFO  )&winspool_ProxyInfo,
                  57,
                  0,
                  IDL_handle);
    
}


DWORD RpcReplyOpenPrinter( 
    /* [in] */ handle_t IDL_handle)
{

    CLIENT_CALL_RETURN _RetVal;

    _RetVal = NdrClientCall3(
                  ( PMIDL_STUBLESS_PROXY_INFO  )&winspool_ProxyInfo,
                  58,
                  0,
                  IDL_handle);
    return ( DWORD  )_RetVal.Simple;
    
}


DWORD RpcRouterReplyPrinter( 
    /* [in] */ handle_t IDL_handle)
{

    CLIENT_CALL_RETURN _RetVal;

    _RetVal = NdrClientCall3(
                  ( PMIDL_STUBLESS_PROXY_INFO  )&winspool_ProxyInfo,
                  59,
                  0,
                  IDL_handle);
    return ( DWORD  )_RetVal.Simple;
    
}


DWORD RpcReplyClosePrinter( 
    /* [in] */ handle_t IDL_handle)
{

    CLIENT_CALL_RETURN _RetVal;

    _RetVal = NdrClientCall3(
                  ( PMIDL_STUBLESS_PROXY_INFO  )&winspool_ProxyInfo,
                  60,
                  0,
                  IDL_handle);
    return ( DWORD  )_RetVal.Simple;
    
}


DWORD RpcAddPortEx( 
    /* [in] */ handle_t IDL_handle)
{

    CLIENT_CALL_RETURN _RetVal;

    _RetVal = NdrClientCall3(
                  ( PMIDL_STUBLESS_PROXY_INFO  )&winspool_ProxyInfo,
                  61,
                  0,
                  IDL_handle);
    return ( DWORD  )_RetVal.Simple;
    
}


DWORD RpcRemoteFindFirstPrinterChangeNotification( 
    /* [in] */ handle_t IDL_handle)
{

    CLIENT_CALL_RETURN _RetVal;

    _RetVal = NdrClientCall3(
                  ( PMIDL_STUBLESS_PROXY_INFO  )&winspool_ProxyInfo,
                  62,
                  0,
                  IDL_handle);
    return ( DWORD  )_RetVal.Simple;
    
}


void Opnum63NotUsedOnWire( 
    /* [in] */ handle_t IDL_handle)
{

    NdrClientCall3(
                  ( PMIDL_STUBLESS_PROXY_INFO  )&winspool_ProxyInfo,
                  63,
                  0,
                  IDL_handle);
    
}


void Opnum64NotUsedOnWire( 
    /* [in] */ handle_t IDL_handle)
{

    NdrClientCall3(
                  ( PMIDL_STUBLESS_PROXY_INFO  )&winspool_ProxyInfo,
                  64,
                  0,
                  IDL_handle);
    
}


DWORD RpcRemoteFindFirstPrinterChangeNotificationEx( 
    /* [in] */ PRINTER_HANDLE hPrinter,
    /* [in] */ DWORD fdwFlags,
    /* [in] */ DWORD fdwOptions,
    /* [unique][string][in] */ wchar_t *pszLocalMachine,
    /* [in] */ DWORD dwPrinterLocal,
    /* [unique][in] */ RPC_V2_NOTIFY_OPTIONS *pOptions)
{

    CLIENT_CALL_RETURN _RetVal;

    _RetVal = NdrClientCall3(
                  ( PMIDL_STUBLESS_PROXY_INFO  )&winspool_ProxyInfo,
                  65,
                  0,
                  hPrinter,
                  fdwFlags,
                  fdwOptions,
                  pszLocalMachine,
                  dwPrinterLocal,
                  pOptions);
    return ( DWORD  )_RetVal.Simple;
    
}

extern const GENERIC_BINDING_ROUTINE_PAIR BindingRoutines[ GENERIC_BINDING_TABLE_SIZE ];

#if !defined(__RPC_WIN64__)
#error  Invalid build platform for this stub.
#endif

static const ms2Drprn_MIDL_PROC_FORMAT_STRING ms2Drprn__MIDL_ProcFormatString =
    {
        0,
        {

	/* Procedure RpcEnumPrinters */

			0x0,		/* 0 */
			0x48,		/* Old Flags:  */
/*  2 */	NdrFcLong( 0x0 ),	/* 0 */
/*  6 */	NdrFcShort( 0x0 ),	/* 0 */
/*  8 */	NdrFcShort( 0x10 ),	/* X64 Stack size/offset = 16 */
/* 10 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x0,		/* 0 */
/* 12 */	NdrFcShort( 0x0 ),	/* X64 Stack size/offset = 0 */
/* 14 */	NdrFcShort( 0x0 ),	/* 0 */
/* 16 */	NdrFcShort( 0x8 ),	/* 8 */
/* 18 */	0x44,		/* Oi2 Flags:  has return, has ext, */
			0x1,		/* 1 */
/* 20 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 22 */	NdrFcShort( 0x0 ),	/* 0 */
/* 24 */	NdrFcShort( 0x0 ),	/* 0 */
/* 26 */	NdrFcShort( 0x0 ),	/* 0 */
/* 28 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Return value */

/* 30 */	NdrFcShort( 0x70 ),	/* Flags:  out, return, base type, */
/* 32 */	NdrFcShort( 0x8 ),	/* X64 Stack size/offset = 8 */
/* 34 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

	/* Procedure RpcOpenPrinter */

/* 36 */	0x0,		/* 0 */
			0x48,		/* Old Flags:  */
/* 38 */	NdrFcLong( 0x0 ),	/* 0 */
/* 42 */	NdrFcShort( 0x1 ),	/* 1 */
/* 44 */	NdrFcShort( 0x30 ),	/* X64 Stack size/offset = 48 */
/* 46 */	0x31,		/* FC_BIND_GENERIC */
			0x8,		/* 8 */
/* 48 */	NdrFcShort( 0x0 ),	/* X64 Stack size/offset = 0 */
/* 50 */	0x0,		/* 0 */
			0x5c,		/* FC_PAD */
/* 52 */	NdrFcShort( 0x8 ),	/* 8 */
/* 54 */	NdrFcShort( 0x40 ),	/* 64 */
/* 56 */	0x46,		/* Oi2 Flags:  clt must size, has return, has ext, */
			0x6,		/* 6 */
/* 58 */	0xa,		/* 10 */
			0x5,		/* Ext Flags:  new corr desc, srv corr check, */
/* 60 */	NdrFcShort( 0x0 ),	/* 0 */
/* 62 */	NdrFcShort( 0x1 ),	/* 1 */
/* 64 */	NdrFcShort( 0x0 ),	/* 0 */
/* 66 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Parameter pPrinterName */

/* 68 */	NdrFcShort( 0xb ),	/* Flags:  must size, must free, in, */
/* 70 */	NdrFcShort( 0x0 ),	/* X64 Stack size/offset = 0 */
/* 72 */	NdrFcShort( 0x2 ),	/* Type Offset=2 */

	/* Parameter pHandle */

/* 74 */	NdrFcShort( 0x110 ),	/* Flags:  out, simple ref, */
/* 76 */	NdrFcShort( 0x8 ),	/* X64 Stack size/offset = 8 */
/* 78 */	NdrFcShort( 0xa ),	/* Type Offset=10 */

	/* Parameter pDatatype */

/* 80 */	NdrFcShort( 0xb ),	/* Flags:  must size, must free, in, */
/* 82 */	NdrFcShort( 0x10 ),	/* X64 Stack size/offset = 16 */
/* 84 */	NdrFcShort( 0x2 ),	/* Type Offset=2 */

	/* Parameter pDevModeContainer */

/* 86 */	NdrFcShort( 0x10b ),	/* Flags:  must size, must free, in, simple ref, */
/* 88 */	NdrFcShort( 0x18 ),	/* X64 Stack size/offset = 24 */
/* 90 */	NdrFcShort( 0x1e ),	/* Type Offset=30 */

	/* Parameter AccessRequired */

/* 92 */	NdrFcShort( 0x48 ),	/* Flags:  in, base type, */
/* 94 */	NdrFcShort( 0x20 ),	/* X64 Stack size/offset = 32 */
/* 96 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

	/* Return value */

/* 98 */	NdrFcShort( 0x70 ),	/* Flags:  out, return, base type, */
/* 100 */	NdrFcShort( 0x28 ),	/* X64 Stack size/offset = 40 */
/* 102 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

	/* Procedure RpcSetJob */

/* 104 */	0x0,		/* 0 */
			0x48,		/* Old Flags:  */
/* 106 */	NdrFcLong( 0x0 ),	/* 0 */
/* 110 */	NdrFcShort( 0x2 ),	/* 2 */
/* 112 */	NdrFcShort( 0x10 ),	/* X64 Stack size/offset = 16 */
/* 114 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x0,		/* 0 */
/* 116 */	NdrFcShort( 0x0 ),	/* X64 Stack size/offset = 0 */
/* 118 */	NdrFcShort( 0x0 ),	/* 0 */
/* 120 */	NdrFcShort( 0x8 ),	/* 8 */
/* 122 */	0x44,		/* Oi2 Flags:  has return, has ext, */
			0x1,		/* 1 */
/* 124 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 126 */	NdrFcShort( 0x0 ),	/* 0 */
/* 128 */	NdrFcShort( 0x0 ),	/* 0 */
/* 130 */	NdrFcShort( 0x0 ),	/* 0 */
/* 132 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Return value */

/* 134 */	NdrFcShort( 0x70 ),	/* Flags:  out, return, base type, */
/* 136 */	NdrFcShort( 0x8 ),	/* X64 Stack size/offset = 8 */
/* 138 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

	/* Procedure RpcGetJob */

/* 140 */	0x0,		/* 0 */
			0x48,		/* Old Flags:  */
/* 142 */	NdrFcLong( 0x0 ),	/* 0 */
/* 146 */	NdrFcShort( 0x3 ),	/* 3 */
/* 148 */	NdrFcShort( 0x10 ),	/* X64 Stack size/offset = 16 */
/* 150 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x0,		/* 0 */
/* 152 */	NdrFcShort( 0x0 ),	/* X64 Stack size/offset = 0 */
/* 154 */	NdrFcShort( 0x0 ),	/* 0 */
/* 156 */	NdrFcShort( 0x8 ),	/* 8 */
/* 158 */	0x44,		/* Oi2 Flags:  has return, has ext, */
			0x1,		/* 1 */
/* 160 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 162 */	NdrFcShort( 0x0 ),	/* 0 */
/* 164 */	NdrFcShort( 0x0 ),	/* 0 */
/* 166 */	NdrFcShort( 0x0 ),	/* 0 */
/* 168 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Return value */

/* 170 */	NdrFcShort( 0x70 ),	/* Flags:  out, return, base type, */
/* 172 */	NdrFcShort( 0x8 ),	/* X64 Stack size/offset = 8 */
/* 174 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

	/* Procedure RpcEnumJobs */

/* 176 */	0x0,		/* 0 */
			0x48,		/* Old Flags:  */
/* 178 */	NdrFcLong( 0x0 ),	/* 0 */
/* 182 */	NdrFcShort( 0x4 ),	/* 4 */
/* 184 */	NdrFcShort( 0x10 ),	/* X64 Stack size/offset = 16 */
/* 186 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x0,		/* 0 */
/* 188 */	NdrFcShort( 0x0 ),	/* X64 Stack size/offset = 0 */
/* 190 */	NdrFcShort( 0x0 ),	/* 0 */
/* 192 */	NdrFcShort( 0x8 ),	/* 8 */
/* 194 */	0x44,		/* Oi2 Flags:  has return, has ext, */
			0x1,		/* 1 */
/* 196 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 198 */	NdrFcShort( 0x0 ),	/* 0 */
/* 200 */	NdrFcShort( 0x0 ),	/* 0 */
/* 202 */	NdrFcShort( 0x0 ),	/* 0 */
/* 204 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Return value */

/* 206 */	NdrFcShort( 0x70 ),	/* Flags:  out, return, base type, */
/* 208 */	NdrFcShort( 0x8 ),	/* X64 Stack size/offset = 8 */
/* 210 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

	/* Procedure RpcAddPrinter */

/* 212 */	0x0,		/* 0 */
			0x48,		/* Old Flags:  */
/* 214 */	NdrFcLong( 0x0 ),	/* 0 */
/* 218 */	NdrFcShort( 0x5 ),	/* 5 */
/* 220 */	NdrFcShort( 0x10 ),	/* X64 Stack size/offset = 16 */
/* 222 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x0,		/* 0 */
/* 224 */	NdrFcShort( 0x0 ),	/* X64 Stack size/offset = 0 */
/* 226 */	NdrFcShort( 0x0 ),	/* 0 */
/* 228 */	NdrFcShort( 0x8 ),	/* 8 */
/* 230 */	0x44,		/* Oi2 Flags:  has return, has ext, */
			0x1,		/* 1 */
/* 232 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 234 */	NdrFcShort( 0x0 ),	/* 0 */
/* 236 */	NdrFcShort( 0x0 ),	/* 0 */
/* 238 */	NdrFcShort( 0x0 ),	/* 0 */
/* 240 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Return value */

/* 242 */	NdrFcShort( 0x70 ),	/* Flags:  out, return, base type, */
/* 244 */	NdrFcShort( 0x8 ),	/* X64 Stack size/offset = 8 */
/* 246 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

	/* Procedure RpcDeletePrinter */

/* 248 */	0x0,		/* 0 */
			0x48,		/* Old Flags:  */
/* 250 */	NdrFcLong( 0x0 ),	/* 0 */
/* 254 */	NdrFcShort( 0x6 ),	/* 6 */
/* 256 */	NdrFcShort( 0x10 ),	/* X64 Stack size/offset = 16 */
/* 258 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x0,		/* 0 */
/* 260 */	NdrFcShort( 0x0 ),	/* X64 Stack size/offset = 0 */
/* 262 */	NdrFcShort( 0x0 ),	/* 0 */
/* 264 */	NdrFcShort( 0x8 ),	/* 8 */
/* 266 */	0x44,		/* Oi2 Flags:  has return, has ext, */
			0x1,		/* 1 */
/* 268 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 270 */	NdrFcShort( 0x0 ),	/* 0 */
/* 272 */	NdrFcShort( 0x0 ),	/* 0 */
/* 274 */	NdrFcShort( 0x0 ),	/* 0 */
/* 276 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Return value */

/* 278 */	NdrFcShort( 0x70 ),	/* Flags:  out, return, base type, */
/* 280 */	NdrFcShort( 0x8 ),	/* X64 Stack size/offset = 8 */
/* 282 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

	/* Procedure RpcSetPrinter */

/* 284 */	0x0,		/* 0 */
			0x48,		/* Old Flags:  */
/* 286 */	NdrFcLong( 0x0 ),	/* 0 */
/* 290 */	NdrFcShort( 0x7 ),	/* 7 */
/* 292 */	NdrFcShort( 0x10 ),	/* X64 Stack size/offset = 16 */
/* 294 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x0,		/* 0 */
/* 296 */	NdrFcShort( 0x0 ),	/* X64 Stack size/offset = 0 */
/* 298 */	NdrFcShort( 0x0 ),	/* 0 */
/* 300 */	NdrFcShort( 0x8 ),	/* 8 */
/* 302 */	0x44,		/* Oi2 Flags:  has return, has ext, */
			0x1,		/* 1 */
/* 304 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 306 */	NdrFcShort( 0x0 ),	/* 0 */
/* 308 */	NdrFcShort( 0x0 ),	/* 0 */
/* 310 */	NdrFcShort( 0x0 ),	/* 0 */
/* 312 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Return value */

/* 314 */	NdrFcShort( 0x70 ),	/* Flags:  out, return, base type, */
/* 316 */	NdrFcShort( 0x8 ),	/* X64 Stack size/offset = 8 */
/* 318 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

	/* Procedure RpcGetPrinter */

/* 320 */	0x0,		/* 0 */
			0x48,		/* Old Flags:  */
/* 322 */	NdrFcLong( 0x0 ),	/* 0 */
/* 326 */	NdrFcShort( 0x8 ),	/* 8 */
/* 328 */	NdrFcShort( 0x10 ),	/* X64 Stack size/offset = 16 */
/* 330 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x0,		/* 0 */
/* 332 */	NdrFcShort( 0x0 ),	/* X64 Stack size/offset = 0 */
/* 334 */	NdrFcShort( 0x0 ),	/* 0 */
/* 336 */	NdrFcShort( 0x8 ),	/* 8 */
/* 338 */	0x44,		/* Oi2 Flags:  has return, has ext, */
			0x1,		/* 1 */
/* 340 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 342 */	NdrFcShort( 0x0 ),	/* 0 */
/* 344 */	NdrFcShort( 0x0 ),	/* 0 */
/* 346 */	NdrFcShort( 0x0 ),	/* 0 */
/* 348 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Return value */

/* 350 */	NdrFcShort( 0x70 ),	/* Flags:  out, return, base type, */
/* 352 */	NdrFcShort( 0x8 ),	/* X64 Stack size/offset = 8 */
/* 354 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

	/* Procedure RpcAddPrinterDriver */

/* 356 */	0x0,		/* 0 */
			0x48,		/* Old Flags:  */
/* 358 */	NdrFcLong( 0x0 ),	/* 0 */
/* 362 */	NdrFcShort( 0x9 ),	/* 9 */
/* 364 */	NdrFcShort( 0x10 ),	/* X64 Stack size/offset = 16 */
/* 366 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x0,		/* 0 */
/* 368 */	NdrFcShort( 0x0 ),	/* X64 Stack size/offset = 0 */
/* 370 */	NdrFcShort( 0x0 ),	/* 0 */
/* 372 */	NdrFcShort( 0x8 ),	/* 8 */
/* 374 */	0x44,		/* Oi2 Flags:  has return, has ext, */
			0x1,		/* 1 */
/* 376 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 378 */	NdrFcShort( 0x0 ),	/* 0 */
/* 380 */	NdrFcShort( 0x0 ),	/* 0 */
/* 382 */	NdrFcShort( 0x0 ),	/* 0 */
/* 384 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Return value */

/* 386 */	NdrFcShort( 0x70 ),	/* Flags:  out, return, base type, */
/* 388 */	NdrFcShort( 0x8 ),	/* X64 Stack size/offset = 8 */
/* 390 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

	/* Procedure RpcEnumPrinterDrivers */

/* 392 */	0x0,		/* 0 */
			0x48,		/* Old Flags:  */
/* 394 */	NdrFcLong( 0x0 ),	/* 0 */
/* 398 */	NdrFcShort( 0xa ),	/* 10 */
/* 400 */	NdrFcShort( 0x10 ),	/* X64 Stack size/offset = 16 */
/* 402 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x0,		/* 0 */
/* 404 */	NdrFcShort( 0x0 ),	/* X64 Stack size/offset = 0 */
/* 406 */	NdrFcShort( 0x0 ),	/* 0 */
/* 408 */	NdrFcShort( 0x8 ),	/* 8 */
/* 410 */	0x44,		/* Oi2 Flags:  has return, has ext, */
			0x1,		/* 1 */
/* 412 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 414 */	NdrFcShort( 0x0 ),	/* 0 */
/* 416 */	NdrFcShort( 0x0 ),	/* 0 */
/* 418 */	NdrFcShort( 0x0 ),	/* 0 */
/* 420 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Return value */

/* 422 */	NdrFcShort( 0x70 ),	/* Flags:  out, return, base type, */
/* 424 */	NdrFcShort( 0x8 ),	/* X64 Stack size/offset = 8 */
/* 426 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

	/* Procedure RpcGetPrinterDriver */

/* 428 */	0x0,		/* 0 */
			0x48,		/* Old Flags:  */
/* 430 */	NdrFcLong( 0x0 ),	/* 0 */
/* 434 */	NdrFcShort( 0xb ),	/* 11 */
/* 436 */	NdrFcShort( 0x10 ),	/* X64 Stack size/offset = 16 */
/* 438 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x0,		/* 0 */
/* 440 */	NdrFcShort( 0x0 ),	/* X64 Stack size/offset = 0 */
/* 442 */	NdrFcShort( 0x0 ),	/* 0 */
/* 444 */	NdrFcShort( 0x8 ),	/* 8 */
/* 446 */	0x44,		/* Oi2 Flags:  has return, has ext, */
			0x1,		/* 1 */
/* 448 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 450 */	NdrFcShort( 0x0 ),	/* 0 */
/* 452 */	NdrFcShort( 0x0 ),	/* 0 */
/* 454 */	NdrFcShort( 0x0 ),	/* 0 */
/* 456 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Return value */

/* 458 */	NdrFcShort( 0x70 ),	/* Flags:  out, return, base type, */
/* 460 */	NdrFcShort( 0x8 ),	/* X64 Stack size/offset = 8 */
/* 462 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

	/* Procedure RpcGetPrinterDriverDirectory */

/* 464 */	0x0,		/* 0 */
			0x48,		/* Old Flags:  */
/* 466 */	NdrFcLong( 0x0 ),	/* 0 */
/* 470 */	NdrFcShort( 0xc ),	/* 12 */
/* 472 */	NdrFcShort( 0x10 ),	/* X64 Stack size/offset = 16 */
/* 474 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x0,		/* 0 */
/* 476 */	NdrFcShort( 0x0 ),	/* X64 Stack size/offset = 0 */
/* 478 */	NdrFcShort( 0x0 ),	/* 0 */
/* 480 */	NdrFcShort( 0x8 ),	/* 8 */
/* 482 */	0x44,		/* Oi2 Flags:  has return, has ext, */
			0x1,		/* 1 */
/* 484 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 486 */	NdrFcShort( 0x0 ),	/* 0 */
/* 488 */	NdrFcShort( 0x0 ),	/* 0 */
/* 490 */	NdrFcShort( 0x0 ),	/* 0 */
/* 492 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Return value */

/* 494 */	NdrFcShort( 0x70 ),	/* Flags:  out, return, base type, */
/* 496 */	NdrFcShort( 0x8 ),	/* X64 Stack size/offset = 8 */
/* 498 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

	/* Procedure RpcDeletePrinterDriver */

/* 500 */	0x0,		/* 0 */
			0x48,		/* Old Flags:  */
/* 502 */	NdrFcLong( 0x0 ),	/* 0 */
/* 506 */	NdrFcShort( 0xd ),	/* 13 */
/* 508 */	NdrFcShort( 0x10 ),	/* X64 Stack size/offset = 16 */
/* 510 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x0,		/* 0 */
/* 512 */	NdrFcShort( 0x0 ),	/* X64 Stack size/offset = 0 */
/* 514 */	NdrFcShort( 0x0 ),	/* 0 */
/* 516 */	NdrFcShort( 0x8 ),	/* 8 */
/* 518 */	0x44,		/* Oi2 Flags:  has return, has ext, */
			0x1,		/* 1 */
/* 520 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 522 */	NdrFcShort( 0x0 ),	/* 0 */
/* 524 */	NdrFcShort( 0x0 ),	/* 0 */
/* 526 */	NdrFcShort( 0x0 ),	/* 0 */
/* 528 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Return value */

/* 530 */	NdrFcShort( 0x70 ),	/* Flags:  out, return, base type, */
/* 532 */	NdrFcShort( 0x8 ),	/* X64 Stack size/offset = 8 */
/* 534 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

	/* Procedure RpcAddPrintProcessor */

/* 536 */	0x0,		/* 0 */
			0x48,		/* Old Flags:  */
/* 538 */	NdrFcLong( 0x0 ),	/* 0 */
/* 542 */	NdrFcShort( 0xe ),	/* 14 */
/* 544 */	NdrFcShort( 0x10 ),	/* X64 Stack size/offset = 16 */
/* 546 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x0,		/* 0 */
/* 548 */	NdrFcShort( 0x0 ),	/* X64 Stack size/offset = 0 */
/* 550 */	NdrFcShort( 0x0 ),	/* 0 */
/* 552 */	NdrFcShort( 0x8 ),	/* 8 */
/* 554 */	0x44,		/* Oi2 Flags:  has return, has ext, */
			0x1,		/* 1 */
/* 556 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 558 */	NdrFcShort( 0x0 ),	/* 0 */
/* 560 */	NdrFcShort( 0x0 ),	/* 0 */
/* 562 */	NdrFcShort( 0x0 ),	/* 0 */
/* 564 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Return value */

/* 566 */	NdrFcShort( 0x70 ),	/* Flags:  out, return, base type, */
/* 568 */	NdrFcShort( 0x8 ),	/* X64 Stack size/offset = 8 */
/* 570 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

	/* Procedure RpcEnumPrintProcessors */

/* 572 */	0x0,		/* 0 */
			0x48,		/* Old Flags:  */
/* 574 */	NdrFcLong( 0x0 ),	/* 0 */
/* 578 */	NdrFcShort( 0xf ),	/* 15 */
/* 580 */	NdrFcShort( 0x10 ),	/* X64 Stack size/offset = 16 */
/* 582 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x0,		/* 0 */
/* 584 */	NdrFcShort( 0x0 ),	/* X64 Stack size/offset = 0 */
/* 586 */	NdrFcShort( 0x0 ),	/* 0 */
/* 588 */	NdrFcShort( 0x8 ),	/* 8 */
/* 590 */	0x44,		/* Oi2 Flags:  has return, has ext, */
			0x1,		/* 1 */
/* 592 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 594 */	NdrFcShort( 0x0 ),	/* 0 */
/* 596 */	NdrFcShort( 0x0 ),	/* 0 */
/* 598 */	NdrFcShort( 0x0 ),	/* 0 */
/* 600 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Return value */

/* 602 */	NdrFcShort( 0x70 ),	/* Flags:  out, return, base type, */
/* 604 */	NdrFcShort( 0x8 ),	/* X64 Stack size/offset = 8 */
/* 606 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

	/* Procedure RpcGetPrintProcessorDirectory */

/* 608 */	0x0,		/* 0 */
			0x48,		/* Old Flags:  */
/* 610 */	NdrFcLong( 0x0 ),	/* 0 */
/* 614 */	NdrFcShort( 0x10 ),	/* 16 */
/* 616 */	NdrFcShort( 0x10 ),	/* X64 Stack size/offset = 16 */
/* 618 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x0,		/* 0 */
/* 620 */	NdrFcShort( 0x0 ),	/* X64 Stack size/offset = 0 */
/* 622 */	NdrFcShort( 0x0 ),	/* 0 */
/* 624 */	NdrFcShort( 0x8 ),	/* 8 */
/* 626 */	0x44,		/* Oi2 Flags:  has return, has ext, */
			0x1,		/* 1 */
/* 628 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 630 */	NdrFcShort( 0x0 ),	/* 0 */
/* 632 */	NdrFcShort( 0x0 ),	/* 0 */
/* 634 */	NdrFcShort( 0x0 ),	/* 0 */
/* 636 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Return value */

/* 638 */	NdrFcShort( 0x70 ),	/* Flags:  out, return, base type, */
/* 640 */	NdrFcShort( 0x8 ),	/* X64 Stack size/offset = 8 */
/* 642 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

	/* Procedure RpcStartDocPrinter */

/* 644 */	0x0,		/* 0 */
			0x48,		/* Old Flags:  */
/* 646 */	NdrFcLong( 0x0 ),	/* 0 */
/* 650 */	NdrFcShort( 0x11 ),	/* 17 */
/* 652 */	NdrFcShort( 0x10 ),	/* X64 Stack size/offset = 16 */
/* 654 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x0,		/* 0 */
/* 656 */	NdrFcShort( 0x0 ),	/* X64 Stack size/offset = 0 */
/* 658 */	NdrFcShort( 0x0 ),	/* 0 */
/* 660 */	NdrFcShort( 0x8 ),	/* 8 */
/* 662 */	0x44,		/* Oi2 Flags:  has return, has ext, */
			0x1,		/* 1 */
/* 664 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 666 */	NdrFcShort( 0x0 ),	/* 0 */
/* 668 */	NdrFcShort( 0x0 ),	/* 0 */
/* 670 */	NdrFcShort( 0x0 ),	/* 0 */
/* 672 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Return value */

/* 674 */	NdrFcShort( 0x70 ),	/* Flags:  out, return, base type, */
/* 676 */	NdrFcShort( 0x8 ),	/* X64 Stack size/offset = 8 */
/* 678 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

	/* Procedure RpcStartPagePrinter */

/* 680 */	0x0,		/* 0 */
			0x48,		/* Old Flags:  */
/* 682 */	NdrFcLong( 0x0 ),	/* 0 */
/* 686 */	NdrFcShort( 0x12 ),	/* 18 */
/* 688 */	NdrFcShort( 0x10 ),	/* X64 Stack size/offset = 16 */
/* 690 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x0,		/* 0 */
/* 692 */	NdrFcShort( 0x0 ),	/* X64 Stack size/offset = 0 */
/* 694 */	NdrFcShort( 0x0 ),	/* 0 */
/* 696 */	NdrFcShort( 0x8 ),	/* 8 */
/* 698 */	0x44,		/* Oi2 Flags:  has return, has ext, */
			0x1,		/* 1 */
/* 700 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 702 */	NdrFcShort( 0x0 ),	/* 0 */
/* 704 */	NdrFcShort( 0x0 ),	/* 0 */
/* 706 */	NdrFcShort( 0x0 ),	/* 0 */
/* 708 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Return value */

/* 710 */	NdrFcShort( 0x70 ),	/* Flags:  out, return, base type, */
/* 712 */	NdrFcShort( 0x8 ),	/* X64 Stack size/offset = 8 */
/* 714 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

	/* Procedure RpcWritePrinter */

/* 716 */	0x0,		/* 0 */
			0x48,		/* Old Flags:  */
/* 718 */	NdrFcLong( 0x0 ),	/* 0 */
/* 722 */	NdrFcShort( 0x13 ),	/* 19 */
/* 724 */	NdrFcShort( 0x10 ),	/* X64 Stack size/offset = 16 */
/* 726 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x0,		/* 0 */
/* 728 */	NdrFcShort( 0x0 ),	/* X64 Stack size/offset = 0 */
/* 730 */	NdrFcShort( 0x0 ),	/* 0 */
/* 732 */	NdrFcShort( 0x8 ),	/* 8 */
/* 734 */	0x44,		/* Oi2 Flags:  has return, has ext, */
			0x1,		/* 1 */
/* 736 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 738 */	NdrFcShort( 0x0 ),	/* 0 */
/* 740 */	NdrFcShort( 0x0 ),	/* 0 */
/* 742 */	NdrFcShort( 0x0 ),	/* 0 */
/* 744 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Return value */

/* 746 */	NdrFcShort( 0x70 ),	/* Flags:  out, return, base type, */
/* 748 */	NdrFcShort( 0x8 ),	/* X64 Stack size/offset = 8 */
/* 750 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

	/* Procedure RpcEndPagePrinter */

/* 752 */	0x0,		/* 0 */
			0x48,		/* Old Flags:  */
/* 754 */	NdrFcLong( 0x0 ),	/* 0 */
/* 758 */	NdrFcShort( 0x14 ),	/* 20 */
/* 760 */	NdrFcShort( 0x10 ),	/* X64 Stack size/offset = 16 */
/* 762 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x0,		/* 0 */
/* 764 */	NdrFcShort( 0x0 ),	/* X64 Stack size/offset = 0 */
/* 766 */	NdrFcShort( 0x0 ),	/* 0 */
/* 768 */	NdrFcShort( 0x8 ),	/* 8 */
/* 770 */	0x44,		/* Oi2 Flags:  has return, has ext, */
			0x1,		/* 1 */
/* 772 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 774 */	NdrFcShort( 0x0 ),	/* 0 */
/* 776 */	NdrFcShort( 0x0 ),	/* 0 */
/* 778 */	NdrFcShort( 0x0 ),	/* 0 */
/* 780 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Return value */

/* 782 */	NdrFcShort( 0x70 ),	/* Flags:  out, return, base type, */
/* 784 */	NdrFcShort( 0x8 ),	/* X64 Stack size/offset = 8 */
/* 786 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

	/* Procedure RpcAbortPrinter */

/* 788 */	0x0,		/* 0 */
			0x48,		/* Old Flags:  */
/* 790 */	NdrFcLong( 0x0 ),	/* 0 */
/* 794 */	NdrFcShort( 0x15 ),	/* 21 */
/* 796 */	NdrFcShort( 0x10 ),	/* X64 Stack size/offset = 16 */
/* 798 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x0,		/* 0 */
/* 800 */	NdrFcShort( 0x0 ),	/* X64 Stack size/offset = 0 */
/* 802 */	NdrFcShort( 0x0 ),	/* 0 */
/* 804 */	NdrFcShort( 0x8 ),	/* 8 */
/* 806 */	0x44,		/* Oi2 Flags:  has return, has ext, */
			0x1,		/* 1 */
/* 808 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 810 */	NdrFcShort( 0x0 ),	/* 0 */
/* 812 */	NdrFcShort( 0x0 ),	/* 0 */
/* 814 */	NdrFcShort( 0x0 ),	/* 0 */
/* 816 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Return value */

/* 818 */	NdrFcShort( 0x70 ),	/* Flags:  out, return, base type, */
/* 820 */	NdrFcShort( 0x8 ),	/* X64 Stack size/offset = 8 */
/* 822 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

	/* Procedure RpcReadPrinter */

/* 824 */	0x0,		/* 0 */
			0x48,		/* Old Flags:  */
/* 826 */	NdrFcLong( 0x0 ),	/* 0 */
/* 830 */	NdrFcShort( 0x16 ),	/* 22 */
/* 832 */	NdrFcShort( 0x10 ),	/* X64 Stack size/offset = 16 */
/* 834 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x0,		/* 0 */
/* 836 */	NdrFcShort( 0x0 ),	/* X64 Stack size/offset = 0 */
/* 838 */	NdrFcShort( 0x0 ),	/* 0 */
/* 840 */	NdrFcShort( 0x8 ),	/* 8 */
/* 842 */	0x44,		/* Oi2 Flags:  has return, has ext, */
			0x1,		/* 1 */
/* 844 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 846 */	NdrFcShort( 0x0 ),	/* 0 */
/* 848 */	NdrFcShort( 0x0 ),	/* 0 */
/* 850 */	NdrFcShort( 0x0 ),	/* 0 */
/* 852 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Return value */

/* 854 */	NdrFcShort( 0x70 ),	/* Flags:  out, return, base type, */
/* 856 */	NdrFcShort( 0x8 ),	/* X64 Stack size/offset = 8 */
/* 858 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

	/* Procedure RpcEndDocPrinter */

/* 860 */	0x0,		/* 0 */
			0x48,		/* Old Flags:  */
/* 862 */	NdrFcLong( 0x0 ),	/* 0 */
/* 866 */	NdrFcShort( 0x17 ),	/* 23 */
/* 868 */	NdrFcShort( 0x10 ),	/* X64 Stack size/offset = 16 */
/* 870 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x0,		/* 0 */
/* 872 */	NdrFcShort( 0x0 ),	/* X64 Stack size/offset = 0 */
/* 874 */	NdrFcShort( 0x0 ),	/* 0 */
/* 876 */	NdrFcShort( 0x8 ),	/* 8 */
/* 878 */	0x44,		/* Oi2 Flags:  has return, has ext, */
			0x1,		/* 1 */
/* 880 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 882 */	NdrFcShort( 0x0 ),	/* 0 */
/* 884 */	NdrFcShort( 0x0 ),	/* 0 */
/* 886 */	NdrFcShort( 0x0 ),	/* 0 */
/* 888 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Return value */

/* 890 */	NdrFcShort( 0x70 ),	/* Flags:  out, return, base type, */
/* 892 */	NdrFcShort( 0x8 ),	/* X64 Stack size/offset = 8 */
/* 894 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

	/* Procedure RpcAddJob */

/* 896 */	0x0,		/* 0 */
			0x48,		/* Old Flags:  */
/* 898 */	NdrFcLong( 0x0 ),	/* 0 */
/* 902 */	NdrFcShort( 0x18 ),	/* 24 */
/* 904 */	NdrFcShort( 0x10 ),	/* X64 Stack size/offset = 16 */
/* 906 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x0,		/* 0 */
/* 908 */	NdrFcShort( 0x0 ),	/* X64 Stack size/offset = 0 */
/* 910 */	NdrFcShort( 0x0 ),	/* 0 */
/* 912 */	NdrFcShort( 0x8 ),	/* 8 */
/* 914 */	0x44,		/* Oi2 Flags:  has return, has ext, */
			0x1,		/* 1 */
/* 916 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 918 */	NdrFcShort( 0x0 ),	/* 0 */
/* 920 */	NdrFcShort( 0x0 ),	/* 0 */
/* 922 */	NdrFcShort( 0x0 ),	/* 0 */
/* 924 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Return value */

/* 926 */	NdrFcShort( 0x70 ),	/* Flags:  out, return, base type, */
/* 928 */	NdrFcShort( 0x8 ),	/* X64 Stack size/offset = 8 */
/* 930 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

	/* Procedure RpcScheduleJob */

/* 932 */	0x0,		/* 0 */
			0x48,		/* Old Flags:  */
/* 934 */	NdrFcLong( 0x0 ),	/* 0 */
/* 938 */	NdrFcShort( 0x19 ),	/* 25 */
/* 940 */	NdrFcShort( 0x10 ),	/* X64 Stack size/offset = 16 */
/* 942 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x0,		/* 0 */
/* 944 */	NdrFcShort( 0x0 ),	/* X64 Stack size/offset = 0 */
/* 946 */	NdrFcShort( 0x0 ),	/* 0 */
/* 948 */	NdrFcShort( 0x8 ),	/* 8 */
/* 950 */	0x44,		/* Oi2 Flags:  has return, has ext, */
			0x1,		/* 1 */
/* 952 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 954 */	NdrFcShort( 0x0 ),	/* 0 */
/* 956 */	NdrFcShort( 0x0 ),	/* 0 */
/* 958 */	NdrFcShort( 0x0 ),	/* 0 */
/* 960 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Return value */

/* 962 */	NdrFcShort( 0x70 ),	/* Flags:  out, return, base type, */
/* 964 */	NdrFcShort( 0x8 ),	/* X64 Stack size/offset = 8 */
/* 966 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

	/* Procedure RpcGetPrinterData */

/* 968 */	0x0,		/* 0 */
			0x48,		/* Old Flags:  */
/* 970 */	NdrFcLong( 0x0 ),	/* 0 */
/* 974 */	NdrFcShort( 0x1a ),	/* 26 */
/* 976 */	NdrFcShort( 0x10 ),	/* X64 Stack size/offset = 16 */
/* 978 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x0,		/* 0 */
/* 980 */	NdrFcShort( 0x0 ),	/* X64 Stack size/offset = 0 */
/* 982 */	NdrFcShort( 0x0 ),	/* 0 */
/* 984 */	NdrFcShort( 0x8 ),	/* 8 */
/* 986 */	0x44,		/* Oi2 Flags:  has return, has ext, */
			0x1,		/* 1 */
/* 988 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 990 */	NdrFcShort( 0x0 ),	/* 0 */
/* 992 */	NdrFcShort( 0x0 ),	/* 0 */
/* 994 */	NdrFcShort( 0x0 ),	/* 0 */
/* 996 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Return value */

/* 998 */	NdrFcShort( 0x70 ),	/* Flags:  out, return, base type, */
/* 1000 */	NdrFcShort( 0x8 ),	/* X64 Stack size/offset = 8 */
/* 1002 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

	/* Procedure RpcSetPrinterData */

/* 1004 */	0x0,		/* 0 */
			0x48,		/* Old Flags:  */
/* 1006 */	NdrFcLong( 0x0 ),	/* 0 */
/* 1010 */	NdrFcShort( 0x1b ),	/* 27 */
/* 1012 */	NdrFcShort( 0x10 ),	/* X64 Stack size/offset = 16 */
/* 1014 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x0,		/* 0 */
/* 1016 */	NdrFcShort( 0x0 ),	/* X64 Stack size/offset = 0 */
/* 1018 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1020 */	NdrFcShort( 0x8 ),	/* 8 */
/* 1022 */	0x44,		/* Oi2 Flags:  has return, has ext, */
			0x1,		/* 1 */
/* 1024 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 1026 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1028 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1030 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1032 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Return value */

/* 1034 */	NdrFcShort( 0x70 ),	/* Flags:  out, return, base type, */
/* 1036 */	NdrFcShort( 0x8 ),	/* X64 Stack size/offset = 8 */
/* 1038 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

	/* Procedure RpcWaitForPrinterChange */

/* 1040 */	0x0,		/* 0 */
			0x48,		/* Old Flags:  */
/* 1042 */	NdrFcLong( 0x0 ),	/* 0 */
/* 1046 */	NdrFcShort( 0x1c ),	/* 28 */
/* 1048 */	NdrFcShort( 0x10 ),	/* X64 Stack size/offset = 16 */
/* 1050 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x0,		/* 0 */
/* 1052 */	NdrFcShort( 0x0 ),	/* X64 Stack size/offset = 0 */
/* 1054 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1056 */	NdrFcShort( 0x8 ),	/* 8 */
/* 1058 */	0x44,		/* Oi2 Flags:  has return, has ext, */
			0x1,		/* 1 */
/* 1060 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 1062 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1064 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1066 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1068 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Return value */

/* 1070 */	NdrFcShort( 0x70 ),	/* Flags:  out, return, base type, */
/* 1072 */	NdrFcShort( 0x8 ),	/* X64 Stack size/offset = 8 */
/* 1074 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

	/* Procedure RpcClosePrinter */

/* 1076 */	0x0,		/* 0 */
			0x48,		/* Old Flags:  */
/* 1078 */	NdrFcLong( 0x0 ),	/* 0 */
/* 1082 */	NdrFcShort( 0x1d ),	/* 29 */
/* 1084 */	NdrFcShort( 0x10 ),	/* X64 Stack size/offset = 16 */
/* 1086 */	0x30,		/* FC_BIND_CONTEXT */
			0xe0,		/* Ctxt flags:  via ptr, in, out, */
/* 1088 */	NdrFcShort( 0x0 ),	/* X64 Stack size/offset = 0 */
/* 1090 */	0x0,		/* 0 */
			0x0,		/* 0 */
/* 1092 */	NdrFcShort( 0x38 ),	/* 56 */
/* 1094 */	NdrFcShort( 0x40 ),	/* 64 */
/* 1096 */	0x44,		/* Oi2 Flags:  has return, has ext, */
			0x2,		/* 2 */
/* 1098 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 1100 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1102 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1104 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1106 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Parameter phPrinter */

/* 1108 */	NdrFcShort( 0x118 ),	/* Flags:  in, out, simple ref, */
/* 1110 */	NdrFcShort( 0x0 ),	/* X64 Stack size/offset = 0 */
/* 1112 */	NdrFcShort( 0x32 ),	/* Type Offset=50 */

	/* Return value */

/* 1114 */	NdrFcShort( 0x70 ),	/* Flags:  out, return, base type, */
/* 1116 */	NdrFcShort( 0x8 ),	/* X64 Stack size/offset = 8 */
/* 1118 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

	/* Procedure RpcAddForm */

/* 1120 */	0x0,		/* 0 */
			0x48,		/* Old Flags:  */
/* 1122 */	NdrFcLong( 0x0 ),	/* 0 */
/* 1126 */	NdrFcShort( 0x1e ),	/* 30 */
/* 1128 */	NdrFcShort( 0x10 ),	/* X64 Stack size/offset = 16 */
/* 1130 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x0,		/* 0 */
/* 1132 */	NdrFcShort( 0x0 ),	/* X64 Stack size/offset = 0 */
/* 1134 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1136 */	NdrFcShort( 0x8 ),	/* 8 */
/* 1138 */	0x44,		/* Oi2 Flags:  has return, has ext, */
			0x1,		/* 1 */
/* 1140 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 1142 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1144 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1146 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1148 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Return value */

/* 1150 */	NdrFcShort( 0x70 ),	/* Flags:  out, return, base type, */
/* 1152 */	NdrFcShort( 0x8 ),	/* X64 Stack size/offset = 8 */
/* 1154 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

	/* Procedure RpcDeleteForm */

/* 1156 */	0x0,		/* 0 */
			0x48,		/* Old Flags:  */
/* 1158 */	NdrFcLong( 0x0 ),	/* 0 */
/* 1162 */	NdrFcShort( 0x1f ),	/* 31 */
/* 1164 */	NdrFcShort( 0x10 ),	/* X64 Stack size/offset = 16 */
/* 1166 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x0,		/* 0 */
/* 1168 */	NdrFcShort( 0x0 ),	/* X64 Stack size/offset = 0 */
/* 1170 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1172 */	NdrFcShort( 0x8 ),	/* 8 */
/* 1174 */	0x44,		/* Oi2 Flags:  has return, has ext, */
			0x1,		/* 1 */
/* 1176 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 1178 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1180 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1182 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1184 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Return value */

/* 1186 */	NdrFcShort( 0x70 ),	/* Flags:  out, return, base type, */
/* 1188 */	NdrFcShort( 0x8 ),	/* X64 Stack size/offset = 8 */
/* 1190 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

	/* Procedure RpcGetForm */

/* 1192 */	0x0,		/* 0 */
			0x48,		/* Old Flags:  */
/* 1194 */	NdrFcLong( 0x0 ),	/* 0 */
/* 1198 */	NdrFcShort( 0x20 ),	/* 32 */
/* 1200 */	NdrFcShort( 0x10 ),	/* X64 Stack size/offset = 16 */
/* 1202 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x0,		/* 0 */
/* 1204 */	NdrFcShort( 0x0 ),	/* X64 Stack size/offset = 0 */
/* 1206 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1208 */	NdrFcShort( 0x8 ),	/* 8 */
/* 1210 */	0x44,		/* Oi2 Flags:  has return, has ext, */
			0x1,		/* 1 */
/* 1212 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 1214 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1216 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1218 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1220 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Return value */

/* 1222 */	NdrFcShort( 0x70 ),	/* Flags:  out, return, base type, */
/* 1224 */	NdrFcShort( 0x8 ),	/* X64 Stack size/offset = 8 */
/* 1226 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

	/* Procedure RpcSetForm */

/* 1228 */	0x0,		/* 0 */
			0x48,		/* Old Flags:  */
/* 1230 */	NdrFcLong( 0x0 ),	/* 0 */
/* 1234 */	NdrFcShort( 0x21 ),	/* 33 */
/* 1236 */	NdrFcShort( 0x10 ),	/* X64 Stack size/offset = 16 */
/* 1238 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x0,		/* 0 */
/* 1240 */	NdrFcShort( 0x0 ),	/* X64 Stack size/offset = 0 */
/* 1242 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1244 */	NdrFcShort( 0x8 ),	/* 8 */
/* 1246 */	0x44,		/* Oi2 Flags:  has return, has ext, */
			0x1,		/* 1 */
/* 1248 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 1250 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1252 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1254 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1256 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Return value */

/* 1258 */	NdrFcShort( 0x70 ),	/* Flags:  out, return, base type, */
/* 1260 */	NdrFcShort( 0x8 ),	/* X64 Stack size/offset = 8 */
/* 1262 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

	/* Procedure RpcEnumForms */

/* 1264 */	0x0,		/* 0 */
			0x48,		/* Old Flags:  */
/* 1266 */	NdrFcLong( 0x0 ),	/* 0 */
/* 1270 */	NdrFcShort( 0x22 ),	/* 34 */
/* 1272 */	NdrFcShort( 0x10 ),	/* X64 Stack size/offset = 16 */
/* 1274 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x0,		/* 0 */
/* 1276 */	NdrFcShort( 0x0 ),	/* X64 Stack size/offset = 0 */
/* 1278 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1280 */	NdrFcShort( 0x8 ),	/* 8 */
/* 1282 */	0x44,		/* Oi2 Flags:  has return, has ext, */
			0x1,		/* 1 */
/* 1284 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 1286 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1288 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1290 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1292 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Return value */

/* 1294 */	NdrFcShort( 0x70 ),	/* Flags:  out, return, base type, */
/* 1296 */	NdrFcShort( 0x8 ),	/* X64 Stack size/offset = 8 */
/* 1298 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

	/* Procedure RpcEnumPorts */

/* 1300 */	0x0,		/* 0 */
			0x48,		/* Old Flags:  */
/* 1302 */	NdrFcLong( 0x0 ),	/* 0 */
/* 1306 */	NdrFcShort( 0x23 ),	/* 35 */
/* 1308 */	NdrFcShort( 0x10 ),	/* X64 Stack size/offset = 16 */
/* 1310 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x0,		/* 0 */
/* 1312 */	NdrFcShort( 0x0 ),	/* X64 Stack size/offset = 0 */
/* 1314 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1316 */	NdrFcShort( 0x8 ),	/* 8 */
/* 1318 */	0x44,		/* Oi2 Flags:  has return, has ext, */
			0x1,		/* 1 */
/* 1320 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 1322 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1324 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1326 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1328 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Return value */

/* 1330 */	NdrFcShort( 0x70 ),	/* Flags:  out, return, base type, */
/* 1332 */	NdrFcShort( 0x8 ),	/* X64 Stack size/offset = 8 */
/* 1334 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

	/* Procedure RpcEnumMonitors */

/* 1336 */	0x0,		/* 0 */
			0x48,		/* Old Flags:  */
/* 1338 */	NdrFcLong( 0x0 ),	/* 0 */
/* 1342 */	NdrFcShort( 0x24 ),	/* 36 */
/* 1344 */	NdrFcShort( 0x10 ),	/* X64 Stack size/offset = 16 */
/* 1346 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x0,		/* 0 */
/* 1348 */	NdrFcShort( 0x0 ),	/* X64 Stack size/offset = 0 */
/* 1350 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1352 */	NdrFcShort( 0x8 ),	/* 8 */
/* 1354 */	0x44,		/* Oi2 Flags:  has return, has ext, */
			0x1,		/* 1 */
/* 1356 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 1358 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1360 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1362 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1364 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Return value */

/* 1366 */	NdrFcShort( 0x70 ),	/* Flags:  out, return, base type, */
/* 1368 */	NdrFcShort( 0x8 ),	/* X64 Stack size/offset = 8 */
/* 1370 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

	/* Procedure Opnum37NotUsedOnWire */

/* 1372 */	0x0,		/* 0 */
			0x48,		/* Old Flags:  */
/* 1374 */	NdrFcLong( 0x0 ),	/* 0 */
/* 1378 */	NdrFcShort( 0x25 ),	/* 37 */
/* 1380 */	NdrFcShort( 0x8 ),	/* X64 Stack size/offset = 8 */
/* 1382 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x0,		/* 0 */
/* 1384 */	NdrFcShort( 0x0 ),	/* X64 Stack size/offset = 0 */
/* 1386 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1388 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1390 */	0x40,		/* Oi2 Flags:  has ext, */
			0x0,		/* 0 */
/* 1392 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 1394 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1396 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1398 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1400 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Procedure Opnum38NotUsedOnWire */

/* 1402 */	0x0,		/* 0 */
			0x48,		/* Old Flags:  */
/* 1404 */	NdrFcLong( 0x0 ),	/* 0 */
/* 1408 */	NdrFcShort( 0x26 ),	/* 38 */
/* 1410 */	NdrFcShort( 0x8 ),	/* X64 Stack size/offset = 8 */
/* 1412 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x0,		/* 0 */
/* 1414 */	NdrFcShort( 0x0 ),	/* X64 Stack size/offset = 0 */
/* 1416 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1418 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1420 */	0x40,		/* Oi2 Flags:  has ext, */
			0x0,		/* 0 */
/* 1422 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 1424 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1426 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1428 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1430 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Procedure RpcDeletePort */

/* 1432 */	0x0,		/* 0 */
			0x48,		/* Old Flags:  */
/* 1434 */	NdrFcLong( 0x0 ),	/* 0 */
/* 1438 */	NdrFcShort( 0x27 ),	/* 39 */
/* 1440 */	NdrFcShort( 0x10 ),	/* X64 Stack size/offset = 16 */
/* 1442 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x0,		/* 0 */
/* 1444 */	NdrFcShort( 0x0 ),	/* X64 Stack size/offset = 0 */
/* 1446 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1448 */	NdrFcShort( 0x8 ),	/* 8 */
/* 1450 */	0x44,		/* Oi2 Flags:  has return, has ext, */
			0x1,		/* 1 */
/* 1452 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 1454 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1456 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1458 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1460 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Return value */

/* 1462 */	NdrFcShort( 0x70 ),	/* Flags:  out, return, base type, */
/* 1464 */	NdrFcShort( 0x8 ),	/* X64 Stack size/offset = 8 */
/* 1466 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

	/* Procedure RpcCreatePrinterIC */

/* 1468 */	0x0,		/* 0 */
			0x48,		/* Old Flags:  */
/* 1470 */	NdrFcLong( 0x0 ),	/* 0 */
/* 1474 */	NdrFcShort( 0x28 ),	/* 40 */
/* 1476 */	NdrFcShort( 0x10 ),	/* X64 Stack size/offset = 16 */
/* 1478 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x0,		/* 0 */
/* 1480 */	NdrFcShort( 0x0 ),	/* X64 Stack size/offset = 0 */
/* 1482 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1484 */	NdrFcShort( 0x8 ),	/* 8 */
/* 1486 */	0x44,		/* Oi2 Flags:  has return, has ext, */
			0x1,		/* 1 */
/* 1488 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 1490 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1492 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1494 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1496 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Return value */

/* 1498 */	NdrFcShort( 0x70 ),	/* Flags:  out, return, base type, */
/* 1500 */	NdrFcShort( 0x8 ),	/* X64 Stack size/offset = 8 */
/* 1502 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

	/* Procedure RpcPlayGdiScriptOnPrinterIC */

/* 1504 */	0x0,		/* 0 */
			0x48,		/* Old Flags:  */
/* 1506 */	NdrFcLong( 0x0 ),	/* 0 */
/* 1510 */	NdrFcShort( 0x29 ),	/* 41 */
/* 1512 */	NdrFcShort( 0x10 ),	/* X64 Stack size/offset = 16 */
/* 1514 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x0,		/* 0 */
/* 1516 */	NdrFcShort( 0x0 ),	/* X64 Stack size/offset = 0 */
/* 1518 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1520 */	NdrFcShort( 0x8 ),	/* 8 */
/* 1522 */	0x44,		/* Oi2 Flags:  has return, has ext, */
			0x1,		/* 1 */
/* 1524 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 1526 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1528 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1530 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1532 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Return value */

/* 1534 */	NdrFcShort( 0x70 ),	/* Flags:  out, return, base type, */
/* 1536 */	NdrFcShort( 0x8 ),	/* X64 Stack size/offset = 8 */
/* 1538 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

	/* Procedure RpcDeletePrinterIC */

/* 1540 */	0x0,		/* 0 */
			0x48,		/* Old Flags:  */
/* 1542 */	NdrFcLong( 0x0 ),	/* 0 */
/* 1546 */	NdrFcShort( 0x2a ),	/* 42 */
/* 1548 */	NdrFcShort( 0x10 ),	/* X64 Stack size/offset = 16 */
/* 1550 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x0,		/* 0 */
/* 1552 */	NdrFcShort( 0x0 ),	/* X64 Stack size/offset = 0 */
/* 1554 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1556 */	NdrFcShort( 0x8 ),	/* 8 */
/* 1558 */	0x44,		/* Oi2 Flags:  has return, has ext, */
			0x1,		/* 1 */
/* 1560 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 1562 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1564 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1566 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1568 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Return value */

/* 1570 */	NdrFcShort( 0x70 ),	/* Flags:  out, return, base type, */
/* 1572 */	NdrFcShort( 0x8 ),	/* X64 Stack size/offset = 8 */
/* 1574 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

	/* Procedure Opnum43NotUsedOnWire */

/* 1576 */	0x0,		/* 0 */
			0x48,		/* Old Flags:  */
/* 1578 */	NdrFcLong( 0x0 ),	/* 0 */
/* 1582 */	NdrFcShort( 0x2b ),	/* 43 */
/* 1584 */	NdrFcShort( 0x8 ),	/* X64 Stack size/offset = 8 */
/* 1586 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x0,		/* 0 */
/* 1588 */	NdrFcShort( 0x0 ),	/* X64 Stack size/offset = 0 */
/* 1590 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1592 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1594 */	0x40,		/* Oi2 Flags:  has ext, */
			0x0,		/* 0 */
/* 1596 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 1598 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1600 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1602 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1604 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Procedure Opnum44NotUsedOnWire */

/* 1606 */	0x0,		/* 0 */
			0x48,		/* Old Flags:  */
/* 1608 */	NdrFcLong( 0x0 ),	/* 0 */
/* 1612 */	NdrFcShort( 0x2c ),	/* 44 */
/* 1614 */	NdrFcShort( 0x8 ),	/* X64 Stack size/offset = 8 */
/* 1616 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x0,		/* 0 */
/* 1618 */	NdrFcShort( 0x0 ),	/* X64 Stack size/offset = 0 */
/* 1620 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1622 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1624 */	0x40,		/* Oi2 Flags:  has ext, */
			0x0,		/* 0 */
/* 1626 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 1628 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1630 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1632 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1634 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Procedure Opnum45NotUsedOnWire */

/* 1636 */	0x0,		/* 0 */
			0x48,		/* Old Flags:  */
/* 1638 */	NdrFcLong( 0x0 ),	/* 0 */
/* 1642 */	NdrFcShort( 0x2d ),	/* 45 */
/* 1644 */	NdrFcShort( 0x8 ),	/* X64 Stack size/offset = 8 */
/* 1646 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x0,		/* 0 */
/* 1648 */	NdrFcShort( 0x0 ),	/* X64 Stack size/offset = 0 */
/* 1650 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1652 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1654 */	0x40,		/* Oi2 Flags:  has ext, */
			0x0,		/* 0 */
/* 1656 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 1658 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1660 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1662 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1664 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Procedure RpcAddMonitor */

/* 1666 */	0x0,		/* 0 */
			0x48,		/* Old Flags:  */
/* 1668 */	NdrFcLong( 0x0 ),	/* 0 */
/* 1672 */	NdrFcShort( 0x2e ),	/* 46 */
/* 1674 */	NdrFcShort( 0x10 ),	/* X64 Stack size/offset = 16 */
/* 1676 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x0,		/* 0 */
/* 1678 */	NdrFcShort( 0x0 ),	/* X64 Stack size/offset = 0 */
/* 1680 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1682 */	NdrFcShort( 0x8 ),	/* 8 */
/* 1684 */	0x44,		/* Oi2 Flags:  has return, has ext, */
			0x1,		/* 1 */
/* 1686 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 1688 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1690 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1692 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1694 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Return value */

/* 1696 */	NdrFcShort( 0x70 ),	/* Flags:  out, return, base type, */
/* 1698 */	NdrFcShort( 0x8 ),	/* X64 Stack size/offset = 8 */
/* 1700 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

	/* Procedure RpcDeleteMonitor */

/* 1702 */	0x0,		/* 0 */
			0x48,		/* Old Flags:  */
/* 1704 */	NdrFcLong( 0x0 ),	/* 0 */
/* 1708 */	NdrFcShort( 0x2f ),	/* 47 */
/* 1710 */	NdrFcShort( 0x10 ),	/* X64 Stack size/offset = 16 */
/* 1712 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x0,		/* 0 */
/* 1714 */	NdrFcShort( 0x0 ),	/* X64 Stack size/offset = 0 */
/* 1716 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1718 */	NdrFcShort( 0x8 ),	/* 8 */
/* 1720 */	0x44,		/* Oi2 Flags:  has return, has ext, */
			0x1,		/* 1 */
/* 1722 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 1724 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1726 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1728 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1730 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Return value */

/* 1732 */	NdrFcShort( 0x70 ),	/* Flags:  out, return, base type, */
/* 1734 */	NdrFcShort( 0x8 ),	/* X64 Stack size/offset = 8 */
/* 1736 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

	/* Procedure RpcDeletePrintProcessor */

/* 1738 */	0x0,		/* 0 */
			0x48,		/* Old Flags:  */
/* 1740 */	NdrFcLong( 0x0 ),	/* 0 */
/* 1744 */	NdrFcShort( 0x30 ),	/* 48 */
/* 1746 */	NdrFcShort( 0x10 ),	/* X64 Stack size/offset = 16 */
/* 1748 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x0,		/* 0 */
/* 1750 */	NdrFcShort( 0x0 ),	/* X64 Stack size/offset = 0 */
/* 1752 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1754 */	NdrFcShort( 0x8 ),	/* 8 */
/* 1756 */	0x44,		/* Oi2 Flags:  has return, has ext, */
			0x1,		/* 1 */
/* 1758 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 1760 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1762 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1764 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1766 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Return value */

/* 1768 */	NdrFcShort( 0x70 ),	/* Flags:  out, return, base type, */
/* 1770 */	NdrFcShort( 0x8 ),	/* X64 Stack size/offset = 8 */
/* 1772 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

	/* Procedure Opnum49NotUsedOnWire */

/* 1774 */	0x0,		/* 0 */
			0x48,		/* Old Flags:  */
/* 1776 */	NdrFcLong( 0x0 ),	/* 0 */
/* 1780 */	NdrFcShort( 0x31 ),	/* 49 */
/* 1782 */	NdrFcShort( 0x8 ),	/* X64 Stack size/offset = 8 */
/* 1784 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x0,		/* 0 */
/* 1786 */	NdrFcShort( 0x0 ),	/* X64 Stack size/offset = 0 */
/* 1788 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1790 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1792 */	0x40,		/* Oi2 Flags:  has ext, */
			0x0,		/* 0 */
/* 1794 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 1796 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1798 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1800 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1802 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Procedure Opnum50NotUsedOnWire */

/* 1804 */	0x0,		/* 0 */
			0x48,		/* Old Flags:  */
/* 1806 */	NdrFcLong( 0x0 ),	/* 0 */
/* 1810 */	NdrFcShort( 0x32 ),	/* 50 */
/* 1812 */	NdrFcShort( 0x8 ),	/* X64 Stack size/offset = 8 */
/* 1814 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x0,		/* 0 */
/* 1816 */	NdrFcShort( 0x0 ),	/* X64 Stack size/offset = 0 */
/* 1818 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1820 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1822 */	0x40,		/* Oi2 Flags:  has ext, */
			0x0,		/* 0 */
/* 1824 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 1826 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1828 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1830 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1832 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Procedure RpcEnumPrintProcessorDatatypes */

/* 1834 */	0x0,		/* 0 */
			0x48,		/* Old Flags:  */
/* 1836 */	NdrFcLong( 0x0 ),	/* 0 */
/* 1840 */	NdrFcShort( 0x33 ),	/* 51 */
/* 1842 */	NdrFcShort( 0x10 ),	/* X64 Stack size/offset = 16 */
/* 1844 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x0,		/* 0 */
/* 1846 */	NdrFcShort( 0x0 ),	/* X64 Stack size/offset = 0 */
/* 1848 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1850 */	NdrFcShort( 0x8 ),	/* 8 */
/* 1852 */	0x44,		/* Oi2 Flags:  has return, has ext, */
			0x1,		/* 1 */
/* 1854 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 1856 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1858 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1860 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1862 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Return value */

/* 1864 */	NdrFcShort( 0x70 ),	/* Flags:  out, return, base type, */
/* 1866 */	NdrFcShort( 0x8 ),	/* X64 Stack size/offset = 8 */
/* 1868 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

	/* Procedure RpcResetPrinter */

/* 1870 */	0x0,		/* 0 */
			0x48,		/* Old Flags:  */
/* 1872 */	NdrFcLong( 0x0 ),	/* 0 */
/* 1876 */	NdrFcShort( 0x34 ),	/* 52 */
/* 1878 */	NdrFcShort( 0x10 ),	/* X64 Stack size/offset = 16 */
/* 1880 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x0,		/* 0 */
/* 1882 */	NdrFcShort( 0x0 ),	/* X64 Stack size/offset = 0 */
/* 1884 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1886 */	NdrFcShort( 0x8 ),	/* 8 */
/* 1888 */	0x44,		/* Oi2 Flags:  has return, has ext, */
			0x1,		/* 1 */
/* 1890 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 1892 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1894 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1896 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1898 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Return value */

/* 1900 */	NdrFcShort( 0x70 ),	/* Flags:  out, return, base type, */
/* 1902 */	NdrFcShort( 0x8 ),	/* X64 Stack size/offset = 8 */
/* 1904 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

	/* Procedure RpcGetPrinterDriver2 */

/* 1906 */	0x0,		/* 0 */
			0x48,		/* Old Flags:  */
/* 1908 */	NdrFcLong( 0x0 ),	/* 0 */
/* 1912 */	NdrFcShort( 0x35 ),	/* 53 */
/* 1914 */	NdrFcShort( 0x10 ),	/* X64 Stack size/offset = 16 */
/* 1916 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x0,		/* 0 */
/* 1918 */	NdrFcShort( 0x0 ),	/* X64 Stack size/offset = 0 */
/* 1920 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1922 */	NdrFcShort( 0x8 ),	/* 8 */
/* 1924 */	0x44,		/* Oi2 Flags:  has return, has ext, */
			0x1,		/* 1 */
/* 1926 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 1928 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1930 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1932 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1934 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Return value */

/* 1936 */	NdrFcShort( 0x70 ),	/* Flags:  out, return, base type, */
/* 1938 */	NdrFcShort( 0x8 ),	/* X64 Stack size/offset = 8 */
/* 1940 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

	/* Procedure Opnum54NotUsedOnWire */

/* 1942 */	0x0,		/* 0 */
			0x48,		/* Old Flags:  */
/* 1944 */	NdrFcLong( 0x0 ),	/* 0 */
/* 1948 */	NdrFcShort( 0x36 ),	/* 54 */
/* 1950 */	NdrFcShort( 0x8 ),	/* X64 Stack size/offset = 8 */
/* 1952 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x0,		/* 0 */
/* 1954 */	NdrFcShort( 0x0 ),	/* X64 Stack size/offset = 0 */
/* 1956 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1958 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1960 */	0x40,		/* Oi2 Flags:  has ext, */
			0x0,		/* 0 */
/* 1962 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 1964 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1966 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1968 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1970 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Procedure Opnum55NotUsedOnWire */

/* 1972 */	0x0,		/* 0 */
			0x48,		/* Old Flags:  */
/* 1974 */	NdrFcLong( 0x0 ),	/* 0 */
/* 1978 */	NdrFcShort( 0x37 ),	/* 55 */
/* 1980 */	NdrFcShort( 0x8 ),	/* X64 Stack size/offset = 8 */
/* 1982 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x0,		/* 0 */
/* 1984 */	NdrFcShort( 0x0 ),	/* X64 Stack size/offset = 0 */
/* 1986 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1988 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1990 */	0x40,		/* Oi2 Flags:  has ext, */
			0x0,		/* 0 */
/* 1992 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 1994 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1996 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1998 */	NdrFcShort( 0x0 ),	/* 0 */
/* 2000 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Procedure RpcFindClosePrinterChangeNotification */

/* 2002 */	0x0,		/* 0 */
			0x48,		/* Old Flags:  */
/* 2004 */	NdrFcLong( 0x0 ),	/* 0 */
/* 2008 */	NdrFcShort( 0x38 ),	/* 56 */
/* 2010 */	NdrFcShort( 0x10 ),	/* X64 Stack size/offset = 16 */
/* 2012 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x0,		/* 0 */
/* 2014 */	NdrFcShort( 0x0 ),	/* X64 Stack size/offset = 0 */
/* 2016 */	NdrFcShort( 0x0 ),	/* 0 */
/* 2018 */	NdrFcShort( 0x8 ),	/* 8 */
/* 2020 */	0x44,		/* Oi2 Flags:  has return, has ext, */
			0x1,		/* 1 */
/* 2022 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 2024 */	NdrFcShort( 0x0 ),	/* 0 */
/* 2026 */	NdrFcShort( 0x0 ),	/* 0 */
/* 2028 */	NdrFcShort( 0x0 ),	/* 0 */
/* 2030 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Return value */

/* 2032 */	NdrFcShort( 0x70 ),	/* Flags:  out, return, base type, */
/* 2034 */	NdrFcShort( 0x8 ),	/* X64 Stack size/offset = 8 */
/* 2036 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

	/* Procedure Opnum57NotUsedOnWire */

/* 2038 */	0x0,		/* 0 */
			0x48,		/* Old Flags:  */
/* 2040 */	NdrFcLong( 0x0 ),	/* 0 */
/* 2044 */	NdrFcShort( 0x39 ),	/* 57 */
/* 2046 */	NdrFcShort( 0x8 ),	/* X64 Stack size/offset = 8 */
/* 2048 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x0,		/* 0 */
/* 2050 */	NdrFcShort( 0x0 ),	/* X64 Stack size/offset = 0 */
/* 2052 */	NdrFcShort( 0x0 ),	/* 0 */
/* 2054 */	NdrFcShort( 0x0 ),	/* 0 */
/* 2056 */	0x40,		/* Oi2 Flags:  has ext, */
			0x0,		/* 0 */
/* 2058 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 2060 */	NdrFcShort( 0x0 ),	/* 0 */
/* 2062 */	NdrFcShort( 0x0 ),	/* 0 */
/* 2064 */	NdrFcShort( 0x0 ),	/* 0 */
/* 2066 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Procedure RpcReplyOpenPrinter */

/* 2068 */	0x0,		/* 0 */
			0x48,		/* Old Flags:  */
/* 2070 */	NdrFcLong( 0x0 ),	/* 0 */
/* 2074 */	NdrFcShort( 0x3a ),	/* 58 */
/* 2076 */	NdrFcShort( 0x10 ),	/* X64 Stack size/offset = 16 */
/* 2078 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x0,		/* 0 */
/* 2080 */	NdrFcShort( 0x0 ),	/* X64 Stack size/offset = 0 */
/* 2082 */	NdrFcShort( 0x0 ),	/* 0 */
/* 2084 */	NdrFcShort( 0x8 ),	/* 8 */
/* 2086 */	0x44,		/* Oi2 Flags:  has return, has ext, */
			0x1,		/* 1 */
/* 2088 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 2090 */	NdrFcShort( 0x0 ),	/* 0 */
/* 2092 */	NdrFcShort( 0x0 ),	/* 0 */
/* 2094 */	NdrFcShort( 0x0 ),	/* 0 */
/* 2096 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Return value */

/* 2098 */	NdrFcShort( 0x70 ),	/* Flags:  out, return, base type, */
/* 2100 */	NdrFcShort( 0x8 ),	/* X64 Stack size/offset = 8 */
/* 2102 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

	/* Procedure RpcRouterReplyPrinter */

/* 2104 */	0x0,		/* 0 */
			0x48,		/* Old Flags:  */
/* 2106 */	NdrFcLong( 0x0 ),	/* 0 */
/* 2110 */	NdrFcShort( 0x3b ),	/* 59 */
/* 2112 */	NdrFcShort( 0x10 ),	/* X64 Stack size/offset = 16 */
/* 2114 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x0,		/* 0 */
/* 2116 */	NdrFcShort( 0x0 ),	/* X64 Stack size/offset = 0 */
/* 2118 */	NdrFcShort( 0x0 ),	/* 0 */
/* 2120 */	NdrFcShort( 0x8 ),	/* 8 */
/* 2122 */	0x44,		/* Oi2 Flags:  has return, has ext, */
			0x1,		/* 1 */
/* 2124 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 2126 */	NdrFcShort( 0x0 ),	/* 0 */
/* 2128 */	NdrFcShort( 0x0 ),	/* 0 */
/* 2130 */	NdrFcShort( 0x0 ),	/* 0 */
/* 2132 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Return value */

/* 2134 */	NdrFcShort( 0x70 ),	/* Flags:  out, return, base type, */
/* 2136 */	NdrFcShort( 0x8 ),	/* X64 Stack size/offset = 8 */
/* 2138 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

	/* Procedure RpcReplyClosePrinter */

/* 2140 */	0x0,		/* 0 */
			0x48,		/* Old Flags:  */
/* 2142 */	NdrFcLong( 0x0 ),	/* 0 */
/* 2146 */	NdrFcShort( 0x3c ),	/* 60 */
/* 2148 */	NdrFcShort( 0x10 ),	/* X64 Stack size/offset = 16 */
/* 2150 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x0,		/* 0 */
/* 2152 */	NdrFcShort( 0x0 ),	/* X64 Stack size/offset = 0 */
/* 2154 */	NdrFcShort( 0x0 ),	/* 0 */
/* 2156 */	NdrFcShort( 0x8 ),	/* 8 */
/* 2158 */	0x44,		/* Oi2 Flags:  has return, has ext, */
			0x1,		/* 1 */
/* 2160 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 2162 */	NdrFcShort( 0x0 ),	/* 0 */
/* 2164 */	NdrFcShort( 0x0 ),	/* 0 */
/* 2166 */	NdrFcShort( 0x0 ),	/* 0 */
/* 2168 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Return value */

/* 2170 */	NdrFcShort( 0x70 ),	/* Flags:  out, return, base type, */
/* 2172 */	NdrFcShort( 0x8 ),	/* X64 Stack size/offset = 8 */
/* 2174 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

	/* Procedure RpcAddPortEx */

/* 2176 */	0x0,		/* 0 */
			0x48,		/* Old Flags:  */
/* 2178 */	NdrFcLong( 0x0 ),	/* 0 */
/* 2182 */	NdrFcShort( 0x3d ),	/* 61 */
/* 2184 */	NdrFcShort( 0x10 ),	/* X64 Stack size/offset = 16 */
/* 2186 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x0,		/* 0 */
/* 2188 */	NdrFcShort( 0x0 ),	/* X64 Stack size/offset = 0 */
/* 2190 */	NdrFcShort( 0x0 ),	/* 0 */
/* 2192 */	NdrFcShort( 0x8 ),	/* 8 */
/* 2194 */	0x44,		/* Oi2 Flags:  has return, has ext, */
			0x1,		/* 1 */
/* 2196 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 2198 */	NdrFcShort( 0x0 ),	/* 0 */
/* 2200 */	NdrFcShort( 0x0 ),	/* 0 */
/* 2202 */	NdrFcShort( 0x0 ),	/* 0 */
/* 2204 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Return value */

/* 2206 */	NdrFcShort( 0x70 ),	/* Flags:  out, return, base type, */
/* 2208 */	NdrFcShort( 0x8 ),	/* X64 Stack size/offset = 8 */
/* 2210 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

	/* Procedure RpcRemoteFindFirstPrinterChangeNotification */

/* 2212 */	0x0,		/* 0 */
			0x48,		/* Old Flags:  */
/* 2214 */	NdrFcLong( 0x0 ),	/* 0 */
/* 2218 */	NdrFcShort( 0x3e ),	/* 62 */
/* 2220 */	NdrFcShort( 0x10 ),	/* X64 Stack size/offset = 16 */
/* 2222 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x0,		/* 0 */
/* 2224 */	NdrFcShort( 0x0 ),	/* X64 Stack size/offset = 0 */
/* 2226 */	NdrFcShort( 0x0 ),	/* 0 */
/* 2228 */	NdrFcShort( 0x8 ),	/* 8 */
/* 2230 */	0x44,		/* Oi2 Flags:  has return, has ext, */
			0x1,		/* 1 */
/* 2232 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 2234 */	NdrFcShort( 0x0 ),	/* 0 */
/* 2236 */	NdrFcShort( 0x0 ),	/* 0 */
/* 2238 */	NdrFcShort( 0x0 ),	/* 0 */
/* 2240 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Return value */

/* 2242 */	NdrFcShort( 0x70 ),	/* Flags:  out, return, base type, */
/* 2244 */	NdrFcShort( 0x8 ),	/* X64 Stack size/offset = 8 */
/* 2246 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

	/* Procedure Opnum63NotUsedOnWire */

/* 2248 */	0x0,		/* 0 */
			0x48,		/* Old Flags:  */
/* 2250 */	NdrFcLong( 0x0 ),	/* 0 */
/* 2254 */	NdrFcShort( 0x3f ),	/* 63 */
/* 2256 */	NdrFcShort( 0x8 ),	/* X64 Stack size/offset = 8 */
/* 2258 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x0,		/* 0 */
/* 2260 */	NdrFcShort( 0x0 ),	/* X64 Stack size/offset = 0 */
/* 2262 */	NdrFcShort( 0x0 ),	/* 0 */
/* 2264 */	NdrFcShort( 0x0 ),	/* 0 */
/* 2266 */	0x40,		/* Oi2 Flags:  has ext, */
			0x0,		/* 0 */
/* 2268 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 2270 */	NdrFcShort( 0x0 ),	/* 0 */
/* 2272 */	NdrFcShort( 0x0 ),	/* 0 */
/* 2274 */	NdrFcShort( 0x0 ),	/* 0 */
/* 2276 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Procedure Opnum64NotUsedOnWire */

/* 2278 */	0x0,		/* 0 */
			0x48,		/* Old Flags:  */
/* 2280 */	NdrFcLong( 0x0 ),	/* 0 */
/* 2284 */	NdrFcShort( 0x40 ),	/* 64 */
/* 2286 */	NdrFcShort( 0x8 ),	/* X64 Stack size/offset = 8 */
/* 2288 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x0,		/* 0 */
/* 2290 */	NdrFcShort( 0x0 ),	/* X64 Stack size/offset = 0 */
/* 2292 */	NdrFcShort( 0x0 ),	/* 0 */
/* 2294 */	NdrFcShort( 0x0 ),	/* 0 */
/* 2296 */	0x40,		/* Oi2 Flags:  has ext, */
			0x0,		/* 0 */
/* 2298 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 2300 */	NdrFcShort( 0x0 ),	/* 0 */
/* 2302 */	NdrFcShort( 0x0 ),	/* 0 */
/* 2304 */	NdrFcShort( 0x0 ),	/* 0 */
/* 2306 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Procedure RpcRemoteFindFirstPrinterChangeNotificationEx */

/* 2308 */	0x0,		/* 0 */
			0x48,		/* Old Flags:  */
/* 2310 */	NdrFcLong( 0x0 ),	/* 0 */
/* 2314 */	NdrFcShort( 0x41 ),	/* 65 */
/* 2316 */	NdrFcShort( 0x38 ),	/* X64 Stack size/offset = 56 */
/* 2318 */	0x30,		/* FC_BIND_CONTEXT */
			0x40,		/* Ctxt flags:  in, */
/* 2320 */	NdrFcShort( 0x0 ),	/* X64 Stack size/offset = 0 */
/* 2322 */	0x0,		/* 0 */
			0x0,		/* 0 */
/* 2324 */	NdrFcShort( 0x3c ),	/* 60 */
/* 2326 */	NdrFcShort( 0x8 ),	/* 8 */
/* 2328 */	0x46,		/* Oi2 Flags:  clt must size, has return, has ext, */
			0x7,		/* 7 */
/* 2330 */	0xa,		/* 10 */
			0x5,		/* Ext Flags:  new corr desc, srv corr check, */
/* 2332 */	NdrFcShort( 0x0 ),	/* 0 */
/* 2334 */	NdrFcShort( 0x1 ),	/* 1 */
/* 2336 */	NdrFcShort( 0x0 ),	/* 0 */
/* 2338 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Parameter hPrinter */

/* 2340 */	NdrFcShort( 0x8 ),	/* Flags:  in, */
/* 2342 */	NdrFcShort( 0x0 ),	/* X64 Stack size/offset = 0 */
/* 2344 */	NdrFcShort( 0x36 ),	/* Type Offset=54 */

	/* Parameter fdwFlags */

/* 2346 */	NdrFcShort( 0x48 ),	/* Flags:  in, base type, */
/* 2348 */	NdrFcShort( 0x8 ),	/* X64 Stack size/offset = 8 */
/* 2350 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

	/* Parameter fdwOptions */

/* 2352 */	NdrFcShort( 0x48 ),	/* Flags:  in, base type, */
/* 2354 */	NdrFcShort( 0x10 ),	/* X64 Stack size/offset = 16 */
/* 2356 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

	/* Parameter pszLocalMachine */

/* 2358 */	NdrFcShort( 0xb ),	/* Flags:  must size, must free, in, */
/* 2360 */	NdrFcShort( 0x18 ),	/* X64 Stack size/offset = 24 */
/* 2362 */	NdrFcShort( 0x2 ),	/* Type Offset=2 */

	/* Parameter dwPrinterLocal */

/* 2364 */	NdrFcShort( 0x48 ),	/* Flags:  in, base type, */
/* 2366 */	NdrFcShort( 0x20 ),	/* X64 Stack size/offset = 32 */
/* 2368 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

	/* Parameter pOptions */

/* 2370 */	NdrFcShort( 0xb ),	/* Flags:  must size, must free, in, */
/* 2372 */	NdrFcShort( 0x28 ),	/* X64 Stack size/offset = 40 */
/* 2374 */	NdrFcShort( 0x3a ),	/* Type Offset=58 */

	/* Return value */

/* 2376 */	NdrFcShort( 0x70 ),	/* Flags:  out, return, base type, */
/* 2378 */	NdrFcShort( 0x30 ),	/* X64 Stack size/offset = 48 */
/* 2380 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

			0x0
        }
    };

static const ms2Drprn_MIDL_TYPE_FORMAT_STRING ms2Drprn__MIDL_TypeFormatString =
    {
        0,
        {
			NdrFcShort( 0x0 ),	/* 0 */
/*  2 */	
			0x12, 0x8,	/* FC_UP [simple_pointer] */
/*  4 */	
			0x25,		/* FC_C_WSTRING */
			0x5c,		/* FC_PAD */
/*  6 */	
			0x11, 0x4,	/* FC_RP [alloced_on_stack] */
/*  8 */	NdrFcShort( 0x2 ),	/* Offset= 2 (10) */
/* 10 */	0x30,		/* FC_BIND_CONTEXT */
			0xa0,		/* Ctxt flags:  via ptr, out, */
/* 12 */	0x0,		/* 0 */
			0x0,		/* 0 */
/* 14 */	
			0x11, 0x0,	/* FC_RP */
/* 16 */	NdrFcShort( 0xe ),	/* Offset= 14 (30) */
/* 18 */	
			0x1b,		/* FC_CARRAY */
			0x0,		/* 0 */
/* 20 */	NdrFcShort( 0x1 ),	/* 1 */
/* 22 */	0x19,		/* Corr desc:  field pointer, FC_ULONG */
			0x0,		/*  */
/* 24 */	NdrFcShort( 0x0 ),	/* 0 */
/* 26 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 28 */	0x1,		/* FC_BYTE */
			0x5b,		/* FC_END */
/* 30 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x3,		/* 3 */
/* 32 */	NdrFcShort( 0x10 ),	/* 16 */
/* 34 */	NdrFcShort( 0x0 ),	/* 0 */
/* 36 */	NdrFcShort( 0x6 ),	/* Offset= 6 (42) */
/* 38 */	0x8,		/* FC_LONG */
			0x40,		/* FC_STRUCTPAD4 */
/* 40 */	0x36,		/* FC_POINTER */
			0x5b,		/* FC_END */
/* 42 */	
			0x12, 0x20,	/* FC_UP [maybenull_sizeis] */
/* 44 */	NdrFcShort( 0xffe6 ),	/* Offset= -26 (18) */
/* 46 */	
			0x11, 0x4,	/* FC_RP [alloced_on_stack] */
/* 48 */	NdrFcShort( 0x2 ),	/* Offset= 2 (50) */
/* 50 */	0x30,		/* FC_BIND_CONTEXT */
			0xe1,		/* Ctxt flags:  via ptr, in, out, can't be null */
/* 52 */	0x0,		/* 0 */
			0x0,		/* 0 */
/* 54 */	0x30,		/* FC_BIND_CONTEXT */
			0x41,		/* Ctxt flags:  in, can't be null */
/* 56 */	0x0,		/* 0 */
			0x0,		/* 0 */
/* 58 */	
			0x12, 0x0,	/* FC_UP */
/* 60 */	NdrFcShort( 0x38 ),	/* Offset= 56 (116) */
/* 62 */	
			0x1b,		/* FC_CARRAY */
			0x1,		/* 1 */
/* 64 */	NdrFcShort( 0x2 ),	/* 2 */
/* 66 */	0x19,		/* Corr desc:  field pointer, FC_ULONG */
			0x0,		/*  */
/* 68 */	NdrFcShort( 0xc ),	/* 12 */
/* 70 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 72 */	0x6,		/* FC_SHORT */
			0x5b,		/* FC_END */
/* 74 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x3,		/* 3 */
/* 76 */	NdrFcShort( 0x18 ),	/* 24 */
/* 78 */	NdrFcShort( 0x0 ),	/* 0 */
/* 80 */	NdrFcShort( 0xa ),	/* Offset= 10 (90) */
/* 82 */	0x6,		/* FC_SHORT */
			0x6,		/* FC_SHORT */
/* 84 */	0x8,		/* FC_LONG */
			0x8,		/* FC_LONG */
/* 86 */	0x8,		/* FC_LONG */
			0x36,		/* FC_POINTER */
/* 88 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 90 */	
			0x12, 0x20,	/* FC_UP [maybenull_sizeis] */
/* 92 */	NdrFcShort( 0xffe2 ),	/* Offset= -30 (62) */
/* 94 */	
			0x21,		/* FC_BOGUS_ARRAY */
			0x3,		/* 3 */
/* 96 */	NdrFcShort( 0x0 ),	/* 0 */
/* 98 */	0x19,		/* Corr desc:  field pointer, FC_ULONG */
			0x0,		/*  */
/* 100 */	NdrFcShort( 0x8 ),	/* 8 */
/* 102 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 104 */	NdrFcLong( 0xffffffff ),	/* -1 */
/* 108 */	NdrFcShort( 0x0 ),	/* Corr flags:  */
/* 110 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 112 */	NdrFcShort( 0xffda ),	/* Offset= -38 (74) */
/* 114 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 116 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x3,		/* 3 */
/* 118 */	NdrFcShort( 0x18 ),	/* 24 */
/* 120 */	NdrFcShort( 0x0 ),	/* 0 */
/* 122 */	NdrFcShort( 0x8 ),	/* Offset= 8 (130) */
/* 124 */	0x8,		/* FC_LONG */
			0x8,		/* FC_LONG */
/* 126 */	0x8,		/* FC_LONG */
			0x40,		/* FC_STRUCTPAD4 */
/* 128 */	0x36,		/* FC_POINTER */
			0x5b,		/* FC_END */
/* 130 */	
			0x12, 0x20,	/* FC_UP [maybenull_sizeis] */
/* 132 */	NdrFcShort( 0xffda ),	/* Offset= -38 (94) */

			0x0
        }
    };

static const GENERIC_BINDING_ROUTINE_PAIR BindingRoutines[ GENERIC_BINDING_TABLE_SIZE ] = 
        {
        {
            (GENERIC_BINDING_ROUTINE)STRING_HANDLE_bind,
            (GENERIC_UNBIND_ROUTINE)STRING_HANDLE_unbind
         }
        
        };


static const unsigned short winspool_FormatStringOffsetTable[] =
    {
    0,
    36,
    104,
    140,
    176,
    212,
    248,
    284,
    320,
    356,
    392,
    428,
    464,
    500,
    536,
    572,
    608,
    644,
    680,
    716,
    752,
    788,
    824,
    860,
    896,
    932,
    968,
    1004,
    1040,
    1076,
    1120,
    1156,
    1192,
    1228,
    1264,
    1300,
    1336,
    1372,
    1402,
    1432,
    1468,
    1504,
    1540,
    1576,
    1606,
    1636,
    1666,
    1702,
    1738,
    1774,
    1804,
    1834,
    1870,
    1906,
    1942,
    1972,
    2002,
    2038,
    2068,
    2104,
    2140,
    2176,
    2212,
    2248,
    2278,
    2308
    };



#endif /* defined(_M_AMD64)*/



/* this ALWAYS GENERATED file contains the RPC client stubs */


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

#if defined(_M_AMD64)



extern const GENERIC_BINDING_ROUTINE_PAIR BindingRoutines[ GENERIC_BINDING_TABLE_SIZE ];

#if !defined(__RPC_WIN64__)
#error  Invalid build platform for this stub.
#endif


#include "ndr64types.h"
#include "pshpack8.h"


typedef 
NDR64_FORMAT_CHAR
__midl_frag153_t;
extern const __midl_frag153_t __midl_frag153;

typedef 
struct 
{
    struct _NDR64_POINTER_FORMAT frag1;
}
__midl_frag152_t;
extern const __midl_frag152_t __midl_frag152;

typedef 
struct 
{
    NDR64_FORMAT_UINT32 frag1;
    struct _NDR64_EXPR_VAR frag2;
}
__midl_frag151_t;
extern const __midl_frag151_t __midl_frag151;

typedef 
struct 
{
    struct _NDR64_CONF_ARRAY_HEADER_FORMAT frag1;
    struct _NDR64_ARRAY_ELEMENT_INFO frag2;
}
__midl_frag150_t;
extern const __midl_frag150_t __midl_frag150;

typedef 
struct 
{
    struct _NDR64_STRUCTURE_HEADER_FORMAT frag1;
    struct 
    {
        struct _NDR64_NO_REPEAT_FORMAT frag1;
        struct _NDR64_POINTER_INSTANCE_HEADER_FORMAT frag2;
        struct _NDR64_POINTER_FORMAT frag3;
        NDR64_FORMAT_CHAR frag4;
    } frag2;
}
__midl_frag149_t;
extern const __midl_frag149_t __midl_frag149;

typedef 
NDR64_FORMAT_CHAR
__midl_frag148_t;
extern const __midl_frag148_t __midl_frag148;

typedef 
struct 
{
    NDR64_FORMAT_UINT32 frag1;
    struct _NDR64_EXPR_VAR frag2;
}
__midl_frag145_t;
extern const __midl_frag145_t __midl_frag145;

typedef 
struct 
{
    struct _NDR64_CONF_ARRAY_HEADER_FORMAT frag1;
    struct 
    {
        struct _NDR64_REPEAT_FORMAT frag1;
        struct 
        {
            struct _NDR64_POINTER_INSTANCE_HEADER_FORMAT frag1;
            struct _NDR64_POINTER_FORMAT frag2;
        } frag2;
        NDR64_FORMAT_CHAR frag3;
    } frag2;
    struct _NDR64_ARRAY_ELEMENT_INFO frag3;
}
__midl_frag144_t;
extern const __midl_frag144_t __midl_frag144;

typedef 
struct 
{
    struct _NDR64_BOGUS_STRUCTURE_HEADER_FORMAT frag1;
    struct 
    {
        struct _NDR64_SIMPLE_MEMBER_FORMAT frag1;
        struct _NDR64_SIMPLE_MEMBER_FORMAT frag2;
        struct _NDR64_SIMPLE_MEMBER_FORMAT frag3;
        struct _NDR64_MEMPAD_FORMAT frag4;
        struct _NDR64_SIMPLE_MEMBER_FORMAT frag5;
        struct _NDR64_SIMPLE_MEMBER_FORMAT frag6;
    } frag2;
}
__midl_frag143_t;
extern const __midl_frag143_t __midl_frag143;

typedef 
struct _NDR64_POINTER_FORMAT
__midl_frag142_t;
extern const __midl_frag142_t __midl_frag142;

typedef 
struct _NDR64_CONFORMANT_STRING_FORMAT
__midl_frag140_t;
extern const __midl_frag140_t __midl_frag140;

typedef 
struct _NDR64_POINTER_FORMAT
__midl_frag139_t;
extern const __midl_frag139_t __midl_frag139;

typedef 
struct _NDR64_CONTEXT_HANDLE_FORMAT
__midl_frag136_t;
extern const __midl_frag136_t __midl_frag136;

typedef 
struct 
{
    struct _NDR64_PROC_FORMAT frag1;
    struct _NDR64_BIND_AND_NOTIFY_EXTENSION frag2;
    struct _NDR64_PARAM_FORMAT frag3;
    struct _NDR64_PARAM_FORMAT frag4;
    struct _NDR64_PARAM_FORMAT frag5;
    struct _NDR64_PARAM_FORMAT frag6;
    struct _NDR64_PARAM_FORMAT frag7;
    struct _NDR64_PARAM_FORMAT frag8;
    struct _NDR64_PARAM_FORMAT frag9;
}
__midl_frag135_t;
extern const __midl_frag135_t __midl_frag135;

typedef 
struct 
{
    struct _NDR64_PROC_FORMAT frag1;
    struct _NDR64_BIND_AND_NOTIFY_EXTENSION frag2;
}
__midl_frag134_t;
extern const __midl_frag134_t __midl_frag134;

typedef 
struct 
{
    struct _NDR64_PROC_FORMAT frag1;
    struct _NDR64_BIND_AND_NOTIFY_EXTENSION frag2;
    struct _NDR64_PARAM_FORMAT frag3;
}
__midl_frag131_t;
extern const __midl_frag131_t __midl_frag131;

typedef 
struct _NDR64_CONTEXT_HANDLE_FORMAT
__midl_frag75_t;
extern const __midl_frag75_t __midl_frag75;

typedef 
struct _NDR64_POINTER_FORMAT
__midl_frag74_t;
extern const __midl_frag74_t __midl_frag74;

typedef 
struct 
{
    struct _NDR64_PROC_FORMAT frag1;
    struct _NDR64_BIND_AND_NOTIFY_EXTENSION frag2;
    struct _NDR64_PARAM_FORMAT frag3;
    struct _NDR64_PARAM_FORMAT frag4;
}
__midl_frag73_t;
extern const __midl_frag73_t __midl_frag73;

typedef 
struct 
{
    struct _NDR64_POINTER_FORMAT frag1;
}
__midl_frag16_t;
extern const __midl_frag16_t __midl_frag16;

typedef 
NDR64_FORMAT_CHAR
__midl_frag15_t;
extern const __midl_frag15_t __midl_frag15;

typedef 
struct 
{
    NDR64_FORMAT_UINT32 frag1;
    struct _NDR64_EXPR_VAR frag2;
}
__midl_frag14_t;
extern const __midl_frag14_t __midl_frag14;

typedef 
struct 
{
    struct _NDR64_CONF_ARRAY_HEADER_FORMAT frag1;
    struct _NDR64_ARRAY_ELEMENT_INFO frag2;
}
__midl_frag13_t;
extern const __midl_frag13_t __midl_frag13;

typedef 
struct 
{
    struct _NDR64_BOGUS_STRUCTURE_HEADER_FORMAT frag1;
    struct 
    {
        struct _NDR64_SIMPLE_MEMBER_FORMAT frag1;
        struct _NDR64_MEMPAD_FORMAT frag2;
        struct _NDR64_SIMPLE_MEMBER_FORMAT frag3;
        struct _NDR64_SIMPLE_MEMBER_FORMAT frag4;
    } frag2;
}
__midl_frag12_t;
extern const __midl_frag12_t __midl_frag12;

typedef 
struct _NDR64_POINTER_FORMAT
__midl_frag11_t;
extern const __midl_frag11_t __midl_frag11;

typedef 
struct _NDR64_CONTEXT_HANDLE_FORMAT
__midl_frag8_t;
extern const __midl_frag8_t __midl_frag8;

typedef 
struct _NDR64_POINTER_FORMAT
__midl_frag7_t;
extern const __midl_frag7_t __midl_frag7;

typedef 
struct 
{
    struct _NDR64_PROC_FORMAT frag1;
    struct _NDR64_BIND_AND_NOTIFY_EXTENSION frag2;
    struct _NDR64_PARAM_FORMAT frag3;
    struct _NDR64_PARAM_FORMAT frag4;
    struct _NDR64_PARAM_FORMAT frag5;
    struct _NDR64_PARAM_FORMAT frag6;
    struct _NDR64_PARAM_FORMAT frag7;
    struct _NDR64_PARAM_FORMAT frag8;
}
__midl_frag4_t;
extern const __midl_frag4_t __midl_frag4;

typedef 
NDR64_FORMAT_UINT32
__midl_frag1_t;
extern const __midl_frag1_t __midl_frag1;

static const __midl_frag153_t __midl_frag153 =
0x5    /* FC64_INT32 */;

static const __midl_frag152_t __midl_frag152 =
{ 
/*  */
    { 
    /* *RPC_V2_NOTIFY_OPTIONS_TYPE */
        0x21,    /* FC64_UP */
        (NDR64_UINT8) 32 /* 0x20 */,
        (NDR64_UINT16) 0 /* 0x0 */,
        &__midl_frag144
    }
};

static const __midl_frag151_t __midl_frag151 =
{ 
/*  */
    (NDR64_UINT32) 1 /* 0x1 */,
    { 
    /* struct _NDR64_EXPR_VAR */
        0x3,    /* FC_EXPR_VAR */
        0x6,    /* FC64_UINT32 */
        (NDR64_UINT16) 0 /* 0x0 */,
        (NDR64_UINT32) 12 /* 0xc */
    }
};

static const __midl_frag150_t __midl_frag150 =
{ 
/* *short */
    { 
    /* *short */
        0x41,    /* FC64_CONF_ARRAY */
        (NDR64_UINT8) 1 /* 0x1 */,
        { 
        /* *short */
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0
        },
        (NDR64_UINT8) 0 /* 0x0 */,
        (NDR64_UINT32) 2 /* 0x2 */,
        &__midl_frag151
    },
    { 
    /* struct _NDR64_ARRAY_ELEMENT_INFO */
        (NDR64_UINT32) 2 /* 0x2 */,
        &__midl_frag148
    }
};

static const __midl_frag149_t __midl_frag149 =
{ 
/* RPC_V2_NOTIFY_OPTIONS_TYPE */
    { 
    /* RPC_V2_NOTIFY_OPTIONS_TYPE */
        0x31,    /* FC64_PSTRUCT */
        (NDR64_UINT8) 7 /* 0x7 */,
        { 
        /* RPC_V2_NOTIFY_OPTIONS_TYPE */
            1,
            0,
            0,
            0,
            0,
            0,
            0,
            0
        },
        (NDR64_UINT8) 0 /* 0x0 */,
        (NDR64_UINT32) 24 /* 0x18 */
    },
    { 
    /*  */
        { 
        /* struct _NDR64_NO_REPEAT_FORMAT */
            0x80,    /* FC64_NO_REPEAT */
            (NDR64_UINT8) 0 /* 0x0 */,
            (NDR64_UINT16) 0 /* 0x0 */,
            (NDR64_UINT32) 0 /* 0x0 */
        },
        { 
        /* struct _NDR64_POINTER_INSTANCE_HEADER_FORMAT */
            (NDR64_UINT32) 16 /* 0x10 */,
            (NDR64_UINT32) 0 /* 0x0 */
        },
        { 
        /* *short */
            0x21,    /* FC64_UP */
            (NDR64_UINT8) 32 /* 0x20 */,
            (NDR64_UINT16) 0 /* 0x0 */,
            &__midl_frag150
        },
        0x93    /* FC64_END */
    }
};

static const __midl_frag148_t __midl_frag148 =
0x4    /* FC64_INT16 */;

static const __midl_frag145_t __midl_frag145 =
{ 
/*  */
    (NDR64_UINT32) 1 /* 0x1 */,
    { 
    /* struct _NDR64_EXPR_VAR */
        0x3,    /* FC_EXPR_VAR */
        0x6,    /* FC64_UINT32 */
        (NDR64_UINT16) 0 /* 0x0 */,
        (NDR64_UINT32) 8 /* 0x8 */
    }
};

static const __midl_frag144_t __midl_frag144 =
{ 
/* *RPC_V2_NOTIFY_OPTIONS_TYPE */
    { 
    /* *RPC_V2_NOTIFY_OPTIONS_TYPE */
        0x41,    /* FC64_CONF_ARRAY */
        (NDR64_UINT8) 7 /* 0x7 */,
        { 
        /* *RPC_V2_NOTIFY_OPTIONS_TYPE */
            1,
            0,
            0,
            0,
            0,
            0,
            0,
            0
        },
        (NDR64_UINT8) 0 /* 0x0 */,
        (NDR64_UINT32) 24 /* 0x18 */,
        &__midl_frag145
    },
    { 
    /*  */
        { 
        /* struct _NDR64_REPEAT_FORMAT */
            0x82,    /* FC64_VARIABLE_REPEAT */
            { 
            /* struct _NDR64_REPEAT_FORMAT */
                (NDR64_UINT8) 1 /* 0x1 */,
                (NDR64_UINT8) 0 /* 0x0 */
            },
            (NDR64_UINT16) 0 /* 0x0 */,
            (NDR64_UINT32) 24 /* 0x18 */,
            (NDR64_UINT32) 0 /* 0x0 */,
            (NDR64_UINT32) 1 /* 0x1 */
        },
        { 
        /*  */
            { 
            /* struct _NDR64_POINTER_INSTANCE_HEADER_FORMAT */
                (NDR64_UINT32) 16 /* 0x10 */,
                (NDR64_UINT32) 0 /* 0x0 */
            },
            { 
            /* *short */
                0x21,    /* FC64_UP */
                (NDR64_UINT8) 32 /* 0x20 */,
                (NDR64_UINT16) 0 /* 0x0 */,
                &__midl_frag150
            }
        },
        0x93    /* FC64_END */
    },
    { 
    /* struct _NDR64_ARRAY_ELEMENT_INFO */
        (NDR64_UINT32) 24 /* 0x18 */,
        &__midl_frag149
    }
};

static const __midl_frag143_t __midl_frag143 =
{ 
/* RPC_V2_NOTIFY_OPTIONS */
    { 
    /* RPC_V2_NOTIFY_OPTIONS */
        0x35,    /* FC64_FORCED_BOGUS_STRUCT */
        (NDR64_UINT8) 7 /* 0x7 */,
        { 
        /* RPC_V2_NOTIFY_OPTIONS */
            1,
            1,
            0,
            0,
            0,
            0,
            0,
            0
        },
        (NDR64_UINT8) 0 /* 0x0 */,
        (NDR64_UINT32) 24 /* 0x18 */,
        0,
        0,
        &__midl_frag152,
    },
    { 
    /*  */
        { 
        /* struct _NDR64_SIMPLE_MEMBER_FORMAT */
            0x5,    /* FC64_INT32 */
            (NDR64_UINT8) 0 /* 0x0 */,
            (NDR64_UINT16) 0 /* 0x0 */,
            (NDR64_UINT32) 0 /* 0x0 */
        },
        { 
        /* struct _NDR64_SIMPLE_MEMBER_FORMAT */
            0x5,    /* FC64_INT32 */
            (NDR64_UINT8) 0 /* 0x0 */,
            (NDR64_UINT16) 0 /* 0x0 */,
            (NDR64_UINT32) 0 /* 0x0 */
        },
        { 
        /* struct _NDR64_SIMPLE_MEMBER_FORMAT */
            0x5,    /* FC64_INT32 */
            (NDR64_UINT8) 0 /* 0x0 */,
            (NDR64_UINT16) 0 /* 0x0 */,
            (NDR64_UINT32) 0 /* 0x0 */
        },
        { 
        /* struct _NDR64_MEMPAD_FORMAT */
            0x90,    /* FC64_STRUCTPADN */
            (NDR64_UINT8) 0 /* 0x0 */,
            (NDR64_UINT16) 4 /* 0x4 */,
            (NDR64_UINT32) 0 /* 0x0 */
        },
        { 
        /* struct _NDR64_SIMPLE_MEMBER_FORMAT */
            0x14,    /* FC64_POINTER */
            (NDR64_UINT8) 0 /* 0x0 */,
            (NDR64_UINT16) 0 /* 0x0 */,
            (NDR64_UINT32) 0 /* 0x0 */
        },
        { 
        /* struct _NDR64_SIMPLE_MEMBER_FORMAT */
            0x93,    /* FC64_END */
            (NDR64_UINT8) 0 /* 0x0 */,
            (NDR64_UINT16) 0 /* 0x0 */,
            (NDR64_UINT32) 0 /* 0x0 */
        }
    }
};

static const __midl_frag142_t __midl_frag142 =
{ 
/* *RPC_V2_NOTIFY_OPTIONS */
    0x21,    /* FC64_UP */
    (NDR64_UINT8) 0 /* 0x0 */,
    (NDR64_UINT16) 0 /* 0x0 */,
    &__midl_frag143
};

static const __midl_frag140_t __midl_frag140 =
{ 
/* *wchar_t */
    { 
    /* *wchar_t */
        0x64,    /* FC64_CONF_WCHAR_STRING */
        { 
        /* *wchar_t */
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0
        },
        (NDR64_UINT16) 2 /* 0x2 */
    }
};

static const __midl_frag139_t __midl_frag139 =
{ 
/* *wchar_t */
    0x21,    /* FC64_UP */
    (NDR64_UINT8) 0 /* 0x0 */,
    (NDR64_UINT16) 0 /* 0x0 */,
    &__midl_frag140
};

static const __midl_frag136_t __midl_frag136 =
{ 
/* struct _NDR64_CONTEXT_HANDLE_FORMAT */
    0x70,    /* FC64_BIND_CONTEXT */
    (NDR64_UINT8) 65 /* 0x41 */,
    (NDR64_UINT8) 0 /* 0x0 */,
    (NDR64_UINT8) 0 /* 0x0 */
};

static const __midl_frag135_t __midl_frag135 =
{ 
/* RpcRemoteFindFirstPrinterChangeNotificationEx */
    { 
    /* RpcRemoteFindFirstPrinterChangeNotificationEx */      /* procedure RpcRemoteFindFirstPrinterChangeNotificationEx */
        (NDR64_UINT32) 19660864 /* 0x12c0040 */,    /* explicit handle */ /* IsIntrepreted, ClientMustSize, HasReturn, ServerCorrelation, HasExtensions */
        (NDR64_UINT32) 56 /* 0x38 */ ,  /* Stack size */
        (NDR64_UINT32) 60 /* 0x3c */,
        (NDR64_UINT32) 8 /* 0x8 */,
        (NDR64_UINT16) 0 /* 0x0 */,
        (NDR64_UINT16) 0 /* 0x0 */,
        (NDR64_UINT16) 7 /* 0x7 */,
        (NDR64_UINT16) 8 /* 0x8 */
    },
    { 
    /* struct _NDR64_BIND_AND_NOTIFY_EXTENSION */
        { 
        /* struct _NDR64_BIND_AND_NOTIFY_EXTENSION */
            0x70,    /* FC64_BIND_CONTEXT */
            (NDR64_UINT8) 64 /* 0x40 */,
            0 /* 0x0 */,   /* Stack offset */
            (NDR64_UINT8) 0 /* 0x0 */,
            (NDR64_UINT8) 0 /* 0x0 */
        },
        (NDR64_UINT16) 0 /* 0x0 */      /* Notify index */
    },
    { 
    /* hPrinter */      /* parameter hPrinter */
        &__midl_frag136,
        { 
        /* hPrinter */
            0,
            0,
            0,
            1,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            0
        },    /* [in] */
        (NDR64_UINT16) 0 /* 0x0 */,
        0 /* 0x0 */,   /* Stack offset */
    },
    { 
    /* fdwFlags */      /* parameter fdwFlags */
        &__midl_frag153,
        { 
        /* fdwFlags */
            0,
            0,
            0,
            1,
            0,
            0,
            1,
            1,
            0,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            0
        },    /* [in], Basetype, ByValue */
        (NDR64_UINT16) 0 /* 0x0 */,
        8 /* 0x8 */,   /* Stack offset */
    },
    { 
    /* fdwOptions */      /* parameter fdwOptions */
        &__midl_frag153,
        { 
        /* fdwOptions */
            0,
            0,
            0,
            1,
            0,
            0,
            1,
            1,
            0,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            0
        },    /* [in], Basetype, ByValue */
        (NDR64_UINT16) 0 /* 0x0 */,
        16 /* 0x10 */,   /* Stack offset */
    },
    { 
    /* pszLocalMachine */      /* parameter pszLocalMachine */
        &__midl_frag139,
        { 
        /* pszLocalMachine */
            1,
            1,
            0,
            1,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            0
        },    /* MustSize, MustFree, [in] */
        (NDR64_UINT16) 0 /* 0x0 */,
        24 /* 0x18 */,   /* Stack offset */
    },
    { 
    /* dwPrinterLocal */      /* parameter dwPrinterLocal */
        &__midl_frag153,
        { 
        /* dwPrinterLocal */
            0,
            0,
            0,
            1,
            0,
            0,
            1,
            1,
            0,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            0
        },    /* [in], Basetype, ByValue */
        (NDR64_UINT16) 0 /* 0x0 */,
        32 /* 0x20 */,   /* Stack offset */
    },
    { 
    /* pOptions */      /* parameter pOptions */
        &__midl_frag142,
        { 
        /* pOptions */
            1,
            1,
            0,
            1,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            0
        },    /* MustSize, MustFree, [in] */
        (NDR64_UINT16) 0 /* 0x0 */,
        40 /* 0x28 */,   /* Stack offset */
    },
    { 
    /* DWORD */      /* parameter DWORD */
        &__midl_frag153,
        { 
        /* DWORD */
            0,
            0,
            0,
            0,
            1,
            1,
            1,
            1,
            0,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            0
        },    /* [out], IsReturn, Basetype, ByValue */
        (NDR64_UINT16) 0 /* 0x0 */,
        48 /* 0x30 */,   /* Stack offset */
    }
};

static const __midl_frag134_t __midl_frag134 =
{ 
/* Opnum64NotUsedOnWire */
    { 
    /* Opnum64NotUsedOnWire */      /* procedure Opnum64NotUsedOnWire */
        (NDR64_UINT32) 16777280 /* 0x1000040 */,    /* explicit handle */ /* IsIntrepreted, HasExtensions */
        (NDR64_UINT32) 8 /* 0x8 */ ,  /* Stack size */
        (NDR64_UINT32) 0 /* 0x0 */,
        (NDR64_UINT32) 0 /* 0x0 */,
        (NDR64_UINT16) 0 /* 0x0 */,
        (NDR64_UINT16) 0 /* 0x0 */,
        (NDR64_UINT16) 0 /* 0x0 */,
        (NDR64_UINT16) 8 /* 0x8 */
    },
    { 
    /* struct _NDR64_BIND_AND_NOTIFY_EXTENSION */
        { 
        /* struct _NDR64_BIND_AND_NOTIFY_EXTENSION */
            0x72,    /* FC64_BIND_PRIMITIVE */
            (NDR64_UINT8) 0 /* 0x0 */,
            0 /* 0x0 */,   /* Stack offset */
            (NDR64_UINT8) 0 /* 0x0 */,
            (NDR64_UINT8) 0 /* 0x0 */
        },
        (NDR64_UINT16) 0 /* 0x0 */      /* Notify index */
    }
};

static const __midl_frag131_t __midl_frag131 =
{ 
/* RpcRemoteFindFirstPrinterChangeNotification */
    { 
    /* RpcRemoteFindFirstPrinterChangeNotification */      /* procedure RpcRemoteFindFirstPrinterChangeNotification */
        (NDR64_UINT32) 17301568 /* 0x1080040 */,    /* explicit handle */ /* IsIntrepreted, HasReturn, HasExtensions */
        (NDR64_UINT32) 16 /* 0x10 */ ,  /* Stack size */
        (NDR64_UINT32) 0 /* 0x0 */,
        (NDR64_UINT32) 8 /* 0x8 */,
        (NDR64_UINT16) 0 /* 0x0 */,
        (NDR64_UINT16) 0 /* 0x0 */,
        (NDR64_UINT16) 1 /* 0x1 */,
        (NDR64_UINT16) 8 /* 0x8 */
    },
    { 
    /* struct _NDR64_BIND_AND_NOTIFY_EXTENSION */
        { 
        /* struct _NDR64_BIND_AND_NOTIFY_EXTENSION */
            0x72,    /* FC64_BIND_PRIMITIVE */
            (NDR64_UINT8) 0 /* 0x0 */,
            0 /* 0x0 */,   /* Stack offset */
            (NDR64_UINT8) 0 /* 0x0 */,
            (NDR64_UINT8) 0 /* 0x0 */
        },
        (NDR64_UINT16) 0 /* 0x0 */      /* Notify index */
    },
    { 
    /* DWORD */      /* parameter DWORD */
        &__midl_frag153,
        { 
        /* DWORD */
            0,
            0,
            0,
            0,
            1,
            1,
            1,
            1,
            0,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            0
        },    /* [out], IsReturn, Basetype, ByValue */
        (NDR64_UINT16) 0 /* 0x0 */,
        8 /* 0x8 */,   /* Stack offset */
    }
};

static const __midl_frag75_t __midl_frag75 =
{ 
/* struct _NDR64_CONTEXT_HANDLE_FORMAT */
    0x70,    /* FC64_BIND_CONTEXT */
    (NDR64_UINT8) 225 /* 0xe1 */,
    (NDR64_UINT8) 0 /* 0x0 */,
    (NDR64_UINT8) 0 /* 0x0 */
};

static const __midl_frag74_t __midl_frag74 =
{ 
/* *struct _NDR64_POINTER_FORMAT */
    0x20,    /* FC64_RP */
    (NDR64_UINT8) 4 /* 0x4 */,
    (NDR64_UINT16) 0 /* 0x0 */,
    &__midl_frag75
};

static const __midl_frag73_t __midl_frag73 =
{ 
/* RpcClosePrinter */
    { 
    /* RpcClosePrinter */      /* procedure RpcClosePrinter */
        (NDR64_UINT32) 17301568 /* 0x1080040 */,    /* explicit handle */ /* IsIntrepreted, HasReturn, HasExtensions */
        (NDR64_UINT32) 16 /* 0x10 */ ,  /* Stack size */
        (NDR64_UINT32) 60 /* 0x3c */,
        (NDR64_UINT32) 68 /* 0x44 */,
        (NDR64_UINT16) 0 /* 0x0 */,
        (NDR64_UINT16) 0 /* 0x0 */,
        (NDR64_UINT16) 2 /* 0x2 */,
        (NDR64_UINT16) 8 /* 0x8 */
    },
    { 
    /* struct _NDR64_BIND_AND_NOTIFY_EXTENSION */
        { 
        /* struct _NDR64_BIND_AND_NOTIFY_EXTENSION */
            0x70,    /* FC64_BIND_CONTEXT */
            (NDR64_UINT8) 224 /* 0xe0 */,
            0 /* 0x0 */,   /* Stack offset */
            (NDR64_UINT8) 0 /* 0x0 */,
            (NDR64_UINT8) 0 /* 0x0 */
        },
        (NDR64_UINT16) 0 /* 0x0 */      /* Notify index */
    },
    { 
    /* phPrinter */      /* parameter phPrinter */
        &__midl_frag75,
        { 
        /* phPrinter */
            0,
            0,
            0,
            1,
            1,
            0,
            0,
            0,
            1,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            0
        },    /* [in], [out], SimpleRef */
        (NDR64_UINT16) 0 /* 0x0 */,
        0 /* 0x0 */,   /* Stack offset */
    },
    { 
    /* DWORD */      /* parameter DWORD */
        &__midl_frag153,
        { 
        /* DWORD */
            0,
            0,
            0,
            0,
            1,
            1,
            1,
            1,
            0,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            0
        },    /* [out], IsReturn, Basetype, ByValue */
        (NDR64_UINT16) 0 /* 0x0 */,
        8 /* 0x8 */,   /* Stack offset */
    }
};

static const __midl_frag16_t __midl_frag16 =
{ 
/*  */
    { 
    /* *BYTE */
        0x21,    /* FC64_UP */
        (NDR64_UINT8) 32 /* 0x20 */,
        (NDR64_UINT16) 0 /* 0x0 */,
        &__midl_frag13
    }
};

static const __midl_frag15_t __midl_frag15 =
0x2    /* FC64_INT8 */;

static const __midl_frag14_t __midl_frag14 =
{ 
/*  */
    (NDR64_UINT32) 1 /* 0x1 */,
    { 
    /* struct _NDR64_EXPR_VAR */
        0x3,    /* FC_EXPR_VAR */
        0x6,    /* FC64_UINT32 */
        (NDR64_UINT16) 0 /* 0x0 */,
        (NDR64_UINT32) 0 /* 0x0 */
    }
};

static const __midl_frag13_t __midl_frag13 =
{ 
/* *BYTE */
    { 
    /* *BYTE */
        0x41,    /* FC64_CONF_ARRAY */
        (NDR64_UINT8) 0 /* 0x0 */,
        { 
        /* *BYTE */
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0
        },
        (NDR64_UINT8) 0 /* 0x0 */,
        (NDR64_UINT32) 1 /* 0x1 */,
        &__midl_frag14
    },
    { 
    /* struct _NDR64_ARRAY_ELEMENT_INFO */
        (NDR64_UINT32) 1 /* 0x1 */,
        &__midl_frag15
    }
};

static const __midl_frag12_t __midl_frag12 =
{ 
/* DEVMODE_CONTAINER */
    { 
    /* DEVMODE_CONTAINER */
        0x35,    /* FC64_FORCED_BOGUS_STRUCT */
        (NDR64_UINT8) 7 /* 0x7 */,
        { 
        /* DEVMODE_CONTAINER */
            1,
            1,
            0,
            0,
            0,
            0,
            0,
            0
        },
        (NDR64_UINT8) 0 /* 0x0 */,
        (NDR64_UINT32) 16 /* 0x10 */,
        0,
        0,
        &__midl_frag16,
    },
    { 
    /*  */
        { 
        /* struct _NDR64_SIMPLE_MEMBER_FORMAT */
            0x5,    /* FC64_INT32 */
            (NDR64_UINT8) 0 /* 0x0 */,
            (NDR64_UINT16) 0 /* 0x0 */,
            (NDR64_UINT32) 0 /* 0x0 */
        },
        { 
        /* struct _NDR64_MEMPAD_FORMAT */
            0x90,    /* FC64_STRUCTPADN */
            (NDR64_UINT8) 0 /* 0x0 */,
            (NDR64_UINT16) 4 /* 0x4 */,
            (NDR64_UINT32) 0 /* 0x0 */
        },
        { 
        /* struct _NDR64_SIMPLE_MEMBER_FORMAT */
            0x14,    /* FC64_POINTER */
            (NDR64_UINT8) 0 /* 0x0 */,
            (NDR64_UINT16) 0 /* 0x0 */,
            (NDR64_UINT32) 0 /* 0x0 */
        },
        { 
        /* struct _NDR64_SIMPLE_MEMBER_FORMAT */
            0x93,    /* FC64_END */
            (NDR64_UINT8) 0 /* 0x0 */,
            (NDR64_UINT16) 0 /* 0x0 */,
            (NDR64_UINT32) 0 /* 0x0 */
        }
    }
};

static const __midl_frag11_t __midl_frag11 =
{ 
/* *DEVMODE_CONTAINER */
    0x20,    /* FC64_RP */
    (NDR64_UINT8) 0 /* 0x0 */,
    (NDR64_UINT16) 0 /* 0x0 */,
    &__midl_frag12
};

static const __midl_frag8_t __midl_frag8 =
{ 
/* struct _NDR64_CONTEXT_HANDLE_FORMAT */
    0x70,    /* FC64_BIND_CONTEXT */
    (NDR64_UINT8) 160 /* 0xa0 */,
    (NDR64_UINT8) 0 /* 0x0 */,
    (NDR64_UINT8) 0 /* 0x0 */
};

static const __midl_frag7_t __midl_frag7 =
{ 
/* *struct _NDR64_POINTER_FORMAT */
    0x20,    /* FC64_RP */
    (NDR64_UINT8) 4 /* 0x4 */,
    (NDR64_UINT16) 0 /* 0x0 */,
    &__midl_frag8
};

static const __midl_frag4_t __midl_frag4 =
{ 
/* RpcOpenPrinter */
    { 
    /* RpcOpenPrinter */      /* procedure RpcOpenPrinter */
        (NDR64_UINT32) 19660864 /* 0x12c0040 */,    /* explicit handle */ /* IsIntrepreted, ClientMustSize, HasReturn, ServerCorrelation, HasExtensions */
        (NDR64_UINT32) 48 /* 0x30 */ ,  /* Stack size */
        (NDR64_UINT32) 8 /* 0x8 */,
        (NDR64_UINT32) 68 /* 0x44 */,
        (NDR64_UINT16) 0 /* 0x0 */,
        (NDR64_UINT16) 0 /* 0x0 */,
        (NDR64_UINT16) 6 /* 0x6 */,
        (NDR64_UINT16) 8 /* 0x8 */
    },
    { 
    /* struct _NDR64_BIND_AND_NOTIFY_EXTENSION */
        { 
        /* struct _NDR64_BIND_AND_NOTIFY_EXTENSION */
            0x71,    /* FC64_BIND_GENERIC */
            (NDR64_UINT8) 0 /* 0x0 */,
            0 /* 0x0 */,   /* Stack offset */
            (NDR64_UINT8) 0 /* 0x0 */,
            (NDR64_UINT8) 8 /* 0x8 */
        },
        (NDR64_UINT16) 0 /* 0x0 */      /* Notify index */
    },
    { 
    /* pPrinterName */      /* parameter pPrinterName */
        &__midl_frag139,
        { 
        /* pPrinterName */
            1,
            1,
            0,
            1,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            0
        },    /* MustSize, MustFree, [in] */
        (NDR64_UINT16) 0 /* 0x0 */,
        0 /* 0x0 */,   /* Stack offset */
    },
    { 
    /* pHandle */      /* parameter pHandle */
        &__midl_frag8,
        { 
        /* pHandle */
            0,
            0,
            0,
            0,
            1,
            0,
            0,
            0,
            1,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            0
        },    /* [out], SimpleRef */
        (NDR64_UINT16) 0 /* 0x0 */,
        8 /* 0x8 */,   /* Stack offset */
    },
    { 
    /* pDatatype */      /* parameter pDatatype */
        &__midl_frag139,
        { 
        /* pDatatype */
            1,
            1,
            0,
            1,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            0
        },    /* MustSize, MustFree, [in] */
        (NDR64_UINT16) 0 /* 0x0 */,
        16 /* 0x10 */,   /* Stack offset */
    },
    { 
    /* pDevModeContainer */      /* parameter pDevModeContainer */
        &__midl_frag12,
        { 
        /* pDevModeContainer */
            1,
            1,
            0,
            1,
            0,
            0,
            0,
            0,
            1,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            0
        },    /* MustSize, MustFree, [in], SimpleRef */
        (NDR64_UINT16) 0 /* 0x0 */,
        24 /* 0x18 */,   /* Stack offset */
    },
    { 
    /* AccessRequired */      /* parameter AccessRequired */
        &__midl_frag153,
        { 
        /* AccessRequired */
            0,
            0,
            0,
            1,
            0,
            0,
            1,
            1,
            0,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            0
        },    /* [in], Basetype, ByValue */
        (NDR64_UINT16) 0 /* 0x0 */,
        32 /* 0x20 */,   /* Stack offset */
    },
    { 
    /* DWORD */      /* parameter DWORD */
        &__midl_frag153,
        { 
        /* DWORD */
            0,
            0,
            0,
            0,
            1,
            1,
            1,
            1,
            0,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            0
        },    /* [out], IsReturn, Basetype, ByValue */
        (NDR64_UINT16) 0 /* 0x0 */,
        40 /* 0x28 */,   /* Stack offset */
    }
};

static const __midl_frag1_t __midl_frag1 =
(NDR64_UINT32) 0 /* 0x0 */;


#include "poppack.h"


static const FormatInfoRef winspool_Ndr64ProcTable[] =
    {
    &__midl_frag131,
    &__midl_frag4,
    &__midl_frag131,
    &__midl_frag131,
    &__midl_frag131,
    &__midl_frag131,
    &__midl_frag131,
    &__midl_frag131,
    &__midl_frag131,
    &__midl_frag131,
    &__midl_frag131,
    &__midl_frag131,
    &__midl_frag131,
    &__midl_frag131,
    &__midl_frag131,
    &__midl_frag131,
    &__midl_frag131,
    &__midl_frag131,
    &__midl_frag131,
    &__midl_frag131,
    &__midl_frag131,
    &__midl_frag131,
    &__midl_frag131,
    &__midl_frag131,
    &__midl_frag131,
    &__midl_frag131,
    &__midl_frag131,
    &__midl_frag131,
    &__midl_frag131,
    &__midl_frag73,
    &__midl_frag131,
    &__midl_frag131,
    &__midl_frag131,
    &__midl_frag131,
    &__midl_frag131,
    &__midl_frag131,
    &__midl_frag131,
    &__midl_frag134,
    &__midl_frag134,
    &__midl_frag131,
    &__midl_frag131,
    &__midl_frag131,
    &__midl_frag131,
    &__midl_frag134,
    &__midl_frag134,
    &__midl_frag134,
    &__midl_frag131,
    &__midl_frag131,
    &__midl_frag131,
    &__midl_frag134,
    &__midl_frag134,
    &__midl_frag131,
    &__midl_frag131,
    &__midl_frag131,
    &__midl_frag134,
    &__midl_frag134,
    &__midl_frag131,
    &__midl_frag134,
    &__midl_frag131,
    &__midl_frag131,
    &__midl_frag131,
    &__midl_frag131,
    &__midl_frag131,
    &__midl_frag134,
    &__midl_frag134,
    &__midl_frag135
    };


static const MIDL_STUB_DESC winspool_StubDesc = 
    {
    (void *)& winspool___RpcClientInterface,
    MIDL_user_allocate,
    MIDL_user_free,
    &winspool__MIDL_AutoBindHandle,
    0,
    BindingRoutines,
    0,
    0,
    ms2Drprn__MIDL_TypeFormatString.Format,
    1, /* -error bounds_check flag */
    0x60001, /* Ndr library version */
    0,
    0x801026e, /* MIDL Version 8.1.622 */
    0,
    0,
    0,  /* notify & notify_flag routine table */
    0x2000001, /* MIDL flag */
    0, /* cs routines */
    (void *)& winspool_ProxyInfo,   /* proxy/server info */
    0
    };

static const MIDL_SYNTAX_INFO winspool_SyntaxInfo [  2 ] = 
    {
    {
    {{0x8A885D04,0x1CEB,0x11C9,{0x9F,0xE8,0x08,0x00,0x2B,0x10,0x48,0x60}},{2,0}},
    0,
    ms2Drprn__MIDL_ProcFormatString.Format,
    winspool_FormatStringOffsetTable,
    ms2Drprn__MIDL_TypeFormatString.Format,
    0,
    0,
    0
    }
    ,{
    {{0x71710533,0xbeba,0x4937,{0x83,0x19,0xb5,0xdb,0xef,0x9c,0xcc,0x36}},{1,0}},
    0,
    0 ,
    (unsigned short *) winspool_Ndr64ProcTable,
    0,
    0,
    0,
    0
    }
    };

static const MIDL_STUBLESS_PROXY_INFO winspool_ProxyInfo =
    {
    &winspool_StubDesc,
    ms2Drprn__MIDL_ProcFormatString.Format,
    winspool_FormatStringOffsetTable,
    (RPC_SYNTAX_IDENTIFIER*)&_RpcTransferSyntax,
    2,
    (MIDL_SYNTAX_INFO*)winspool_SyntaxInfo
    
    };

#if _MSC_VER >= 1200
#pragma warning(pop)
#endif


#endif /* defined(_M_AMD64)*/

