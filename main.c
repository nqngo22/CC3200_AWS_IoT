//Nguyen Ngo

// Simplelink includes
#include "simplelink.h"

//Driverlib includes
#include "hw_types.h"
#include "hw_ints.h"
#include "rom.h"
#include "rom_map.h"
#include "interrupt.h"
#include "prcm.h"
#include "utils.h"
#include "uart.h"

//Common interface includes
#include "pinmux.h"
#include "gpio_if.h"
#include "common.h"
#include "uart_if.h"

//lab2
#include "hw_memmap.h"
#include "hw_common_reg.h"
#include "spi.h"
#include "gpio.h"
#include "systick.h"
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include "Adafruit_GFX.h"
#include "Adafruit_SSD1351.h"
#include "glcdfont.h"
#include "test.h"

#define MAX_URI_SIZE 128
#define URI_SIZE MAX_URI_SIZE + 1

#define SPI_IF_BIT_RATE  100000


#define APPLICATION_NAME        "SSL"
#define APPLICATION_VERSION     "1.1.1"

//#define SERVER_NAME                "AHMAIFS2X4J4Y.iot.us-west-2.amazonaws.com"
#define SERVER_NAME    			    "A1I0VEU93IPLGD.iot.us-east-1.amazonaws.com"
#define GOOGLE_DST_PORT             8443

#define SL_SSL_CA_CERT "/cert/rootCA.der"
#define SL_SSL_PRIVATE "/cert/private.der"
#define SL_SSL_CLIENT  "/cert/client.der"


//NEED TO UPDATE THIS FOR IT TO WORK!
#define DATE                10    /* Current Date */
#define MONTH               5     /* Month 1-12 */
#define YEAR                2016  /* Current year */
#define HOUR                11    /* Time - hours */
#define MINUTE              22    /* Time - minutes */
#define SECOND              0     /* Time - seconds */

//#define POSTHEADER "GET /things/CC3200_Thing/shadow"
#define POSTHEADER "POST /things/CC3200_Thing/shadow"
//#define HOSTHEADER "Host: AHMAIFS2X4J4Y.iot.us-west-2.amazonaws.com\r\n"
//#define HOSTHEADER "Host: A1I0VEU93IPLGD.iot.us-west-2.amazonaws.com\r\n"
#define HOSTHEADER "Host: A1I0VEU93IPLGD.iot.us-east-1.amazonaws.com\r\n"
//#define AUTHHEADER "Authorization: SharedAccessSignature sr=swiftsoftware-ns.servicebus.windows.net&sig=6sIkgCiaNbK9R0XEpsKJcQ2Clv8MUMVdQfEVQP09WkM%3d&se=1733661915&skn=EventHubPublisher\r\n"
#define CHEADER0 "x-amz-sns-topic-arn: arn:aws:sns:us-east-1:055734127750:SNS_TOPIC\r\n"
#define CHEADER "Connection: Keep-Alive\r\n"
#define CTHEADER "Content-Type: application/json; charset=utf-8\r\n"
#define CLHEADER1 "Content-Length: "
#define CLHEADER2 "\r\n\r\n"
//Data before the message
#define DATA1 "{\"state\": {\n\r\"desired\" : {\n\r\"message\" : \""
//Data after the message
#define DATA3 "\"\n\r}}}\n\r\n\r"
#define DATA2 ",\"Humidity\":50,\"Location\":\"YourLocation\",\"Room\":\"YourRoom\",\"Info\":\"Sent from CC3200 LaunchPad\"}"

// Application specific status/error codes
typedef enum{
    // Choosing -0x7D0 to avoid overlap w/ host-driver's error codes
    LAN_CONNECTION_FAILED = -0x7D0,
    INTERNET_CONNECTION_FAILED = LAN_CONNECTION_FAILED - 1,
    DEVICE_NOT_IN_STATION_MODE = INTERNET_CONNECTION_FAILED - 1,

    STATUS_CODE_MAX = -0xBB8
}e_AppStatusCodes;

typedef struct
{
   /* time */
   unsigned long tm_sec;
   unsigned long tm_min;
   unsigned long tm_hour;
   /* date */
   unsigned long tm_day;
   unsigned long tm_mon;
   unsigned long tm_year;
   unsigned long tm_week_day; //not required
   unsigned long tm_year_day; //not required
   unsigned long reserved[3];
}SlDateTime;


//*****************************************************************************
//                 GLOBAL VARIABLES -- Start
//*****************************************************************************
volatile unsigned long  g_ulStatus = 0;//SimpleLink Status
unsigned long  g_ulPingPacketsRecv = 0; //Number of Ping Packets received
unsigned long  g_ulGatewayIP = 0; //Network Gateway IP address
unsigned char  g_ucConnectionSSID[SSID_LEN_MAX+1]; //Connection SSID
unsigned char  g_ucConnectionBSSID[BSSID_LEN_MAX]; //Connection BSSID
signed char    *g_Host = SERVER_NAME;
SlDateTime g_time;
#if defined(ccs) || defined(gcc)
extern void (* const g_pfnVectors[])(void);
#endif
#if defined(ewarm)
extern uVectorEntry __vector_table;
#endif
//*****************************************************************************
//                 GLOBAL VARIABLES -- End
//*****************************************************************************
volatile uint64_t bitsequence;
volatile int index;
char ReceivedChar;
char MessageTx[8];
char MessageRx[8];

//****************************************************************************
//                      LOCAL FUNCTION PROTOTYPES
//****************************************************************************
static long WlanConnect();
static int set_time();
static void BoardInit(void);
static long InitializeAppVariables();
static int tls_connect();
static int connectToAccessPoint();
static int http_post(int, char str[100]);

//*****************************************************************************
// SimpleLink Asynchronous Event Handlers -- Start
//*****************************************************************************


//*****************************************************************************
//
//! \brief The Function Handles WLAN Events
//!
//! \param[in]  pWlanEvent - Pointer to WLAN Event Info
//!
//! \return None
//!
//*****************************************************************************
void SimpleLinkWlanEventHandler(SlWlanEvent_t *pWlanEvent)
{
    if(!pWlanEvent)
    {
        return;
    }

    switch(pWlanEvent->Event)
    {
        case SL_WLAN_CONNECT_EVENT:
        {
            SET_STATUS_BIT(g_ulStatus, STATUS_BIT_CONNECTION);

            //
            // Information about the connected AP (like name, MAC etc) will be
            // available in 'slWlanConnectAsyncResponse_t'.
            // Applications can use it if required
            //
            //  slWlanConnectAsyncResponse_t *pEventData = NULL;
            // pEventData = &pWlanEvent->EventData.STAandP2PModeWlanConnected;
            //

            // Copy new connection SSID and BSSID to global parameters
            memcpy(g_ucConnectionSSID,pWlanEvent->EventData.
                   STAandP2PModeWlanConnected.ssid_name,
                   pWlanEvent->EventData.STAandP2PModeWlanConnected.ssid_len);
            memcpy(g_ucConnectionBSSID,
                   pWlanEvent->EventData.STAandP2PModeWlanConnected.bssid,
                   SL_BSSID_LENGTH);

            UART_PRINT("[WLAN EVENT] STA Connected to the AP: %s , "
                       "BSSID: %x:%x:%x:%x:%x:%x\n\r",
                       g_ucConnectionSSID,g_ucConnectionBSSID[0],
                       g_ucConnectionBSSID[1],g_ucConnectionBSSID[2],
                       g_ucConnectionBSSID[3],g_ucConnectionBSSID[4],
                       g_ucConnectionBSSID[5]);
        }
        break;

        case SL_WLAN_DISCONNECT_EVENT:
        {
            slWlanConnectAsyncResponse_t*  pEventData = NULL;

            CLR_STATUS_BIT(g_ulStatus, STATUS_BIT_CONNECTION);
            CLR_STATUS_BIT(g_ulStatus, STATUS_BIT_IP_AQUIRED);

            pEventData = &pWlanEvent->EventData.STAandP2PModeDisconnected;

            // If the user has initiated 'Disconnect' request,
            //'reason_code' is SL_USER_INITIATED_DISCONNECTION
            if(SL_USER_INITIATED_DISCONNECTION == pEventData->reason_code)
            {
                UART_PRINT("[WLAN EVENT]Device disconnected from the AP: %s,"
                    "BSSID: %x:%x:%x:%x:%x:%x on application's request \n\r",
                           g_ucConnectionSSID,g_ucConnectionBSSID[0],
                           g_ucConnectionBSSID[1],g_ucConnectionBSSID[2],
                           g_ucConnectionBSSID[3],g_ucConnectionBSSID[4],
                           g_ucConnectionBSSID[5]);
            }
            else
            {
                UART_PRINT("[WLAN ERROR]Device disconnected from the AP AP: %s, "
                           "BSSID: %x:%x:%x:%x:%x:%x on an ERROR..!! \n\r",
                           g_ucConnectionSSID,g_ucConnectionBSSID[0],
                           g_ucConnectionBSSID[1],g_ucConnectionBSSID[2],
                           g_ucConnectionBSSID[3],g_ucConnectionBSSID[4],
                           g_ucConnectionBSSID[5]);
            }
            memset(g_ucConnectionSSID,0,sizeof(g_ucConnectionSSID));
            memset(g_ucConnectionBSSID,0,sizeof(g_ucConnectionBSSID));
        }
        break;

        default:
        {
            UART_PRINT("[WLAN EVENT] Unexpected event [0x%x]\n\r",
                       pWlanEvent->Event);
        }
        break;
    }
}

//*****************************************************************************
//
//! \brief This function handles network events such as IP acquisition, IP
//!           leased, IP released etc.
//!
//! \param[in]  pNetAppEvent - Pointer to NetApp Event Info
//!
//! \return None
//!
//*****************************************************************************
void SimpleLinkNetAppEventHandler(SlNetAppEvent_t *pNetAppEvent)
{
    if(!pNetAppEvent)
    {
        return;
    }

    switch(pNetAppEvent->Event)
    {
        case SL_NETAPP_IPV4_IPACQUIRED_EVENT:
        {
            SlIpV4AcquiredAsync_t *pEventData = NULL;

            SET_STATUS_BIT(g_ulStatus, STATUS_BIT_IP_AQUIRED);

            //Ip Acquired Event Data
            pEventData = &pNetAppEvent->EventData.ipAcquiredV4;

            //Gateway IP address
            g_ulGatewayIP = pEventData->gateway;

            UART_PRINT("[NETAPP EVENT] IP Acquired: IP=%d.%d.%d.%d , "
                       "Gateway=%d.%d.%d.%d\n\r",
            SL_IPV4_BYTE(pNetAppEvent->EventData.ipAcquiredV4.ip,3),
            SL_IPV4_BYTE(pNetAppEvent->EventData.ipAcquiredV4.ip,2),
            SL_IPV4_BYTE(pNetAppEvent->EventData.ipAcquiredV4.ip,1),
            SL_IPV4_BYTE(pNetAppEvent->EventData.ipAcquiredV4.ip,0),
            SL_IPV4_BYTE(pNetAppEvent->EventData.ipAcquiredV4.gateway,3),
            SL_IPV4_BYTE(pNetAppEvent->EventData.ipAcquiredV4.gateway,2),
            SL_IPV4_BYTE(pNetAppEvent->EventData.ipAcquiredV4.gateway,1),
            SL_IPV4_BYTE(pNetAppEvent->EventData.ipAcquiredV4.gateway,0));
        }
        break;

        default:
        {
            UART_PRINT("[NETAPP EVENT] Unexpected event [0x%x] \n\r",
                       pNetAppEvent->Event);
        }
        break;
    }
}


//*****************************************************************************
//
//! \brief This function handles HTTP server events
//!
//! \param[in]  pServerEvent - Contains the relevant event information
//! \param[in]    pServerResponse - Should be filled by the user with the
//!                                      relevant response information
//!
//! \return None
//!
//****************************************************************************
void SimpleLinkHttpServerCallback(SlHttpServerEvent_t *pHttpEvent,
                                  SlHttpServerResponse_t *pHttpResponse)
{
    // Unused in this application
}

//*****************************************************************************
//
//! \brief This function handles General Events
//!
//! \param[in]     pDevEvent - Pointer to General Event Info
//!
//! \return None
//!
//*****************************************************************************
void SimpleLinkGeneralEventHandler(SlDeviceEvent_t *pDevEvent)
{
    if(!pDevEvent)
    {
        return;
    }

    //
    // Most of the general errors are not FATAL are are to be handled
    // appropriately by the application
    //
    UART_PRINT("[GENERAL EVENT] - ID=[%d] Sender=[%d]\n\n",
               pDevEvent->EventData.deviceEvent.status,
               pDevEvent->EventData.deviceEvent.sender);
}


//*****************************************************************************
//
//! This function handles socket events indication
//!
//! \param[in]      pSock - Pointer to Socket Event Info
//!
//! \return None
//!
//*****************************************************************************
void SimpleLinkSockEventHandler(SlSockEvent_t *pSock)
{
    if(!pSock)
    {
        return;
    }

    switch( pSock->Event )
    {
        case SL_SOCKET_TX_FAILED_EVENT:
            switch( pSock->socketAsyncEvent.SockTxFailData.status)
            {
                case SL_ECLOSE: 
                    UART_PRINT("[SOCK ERROR] - close socket (%d) operation "
                                "failed to transmit all queued packets\n\n", 
                                    pSock->socketAsyncEvent.SockTxFailData.sd);
                    break;
                default: 
                    UART_PRINT("[SOCK ERROR] - TX FAILED  :  socket %d , reason "
                                "(%d) \n\n",
                                pSock->socketAsyncEvent.SockTxFailData.sd, pSock->socketAsyncEvent.SockTxFailData.status);
                  break;
            }
            break;

        default:
        	UART_PRINT("[SOCK EVENT] - Unexpected Event [%x0x]\n\n",pSock->Event);
          break;
    }

}


//*****************************************************************************
// SimpleLink Asynchronous Event Handlers -- End
//*****************************************************************************


//*****************************************************************************
//
//! \brief This function initializes the application variables
//!
//! \param    0 on success else error code
//!
//! \return None
//!
//*****************************************************************************
static long InitializeAppVariables()
{
    g_ulStatus = 0;
    g_ulGatewayIP = 0;
    g_Host = SERVER_NAME;
    memset(g_ucConnectionSSID,0,sizeof(g_ucConnectionSSID));
    memset(g_ucConnectionBSSID,0,sizeof(g_ucConnectionBSSID));
    return SUCCESS;
}


//*****************************************************************************
//! \brief This function puts the device in its default state. It:
//!           - Set the mode to STATION
//!           - Configures connection policy to Auto and AutoSmartConfig
//!           - Deletes all the stored profiles
//!           - Enables DHCP
//!           - Disables Scan policy
//!           - Sets Tx power to maximum
//!           - Sets power policy to normal
//!           - Unregister mDNS services
//!           - Remove all filters
//!
//! \param   none
//! \return  On success, zero is returned. On error, negative is returned
//*****************************************************************************
static long ConfigureSimpleLinkToDefaultState()
{
    SlVersionFull   ver = {0};
    _WlanRxFilterOperationCommandBuff_t  RxFilterIdMask = {0};

    unsigned char ucVal = 1;
    unsigned char ucConfigOpt = 0;
    unsigned char ucConfigLen = 0;
    unsigned char ucPower = 0;

    long lRetVal = -1;
    long lMode = -1;

    lMode = sl_Start(0, 0, 0);
    ASSERT_ON_ERROR(lMode);

    // If the device is not in station-mode, try configuring it in station-mode 
    if (ROLE_STA != lMode)
    {
        if (ROLE_AP == lMode)
        {
            // If the device is in AP mode, we need to wait for this event 
            // before doing anything 
            while(!IS_IP_ACQUIRED(g_ulStatus))
            {
#ifndef SL_PLATFORM_MULTI_THREADED
              _SlNonOsMainLoopTask(); 
#endif
            }
        }

        // Switch to STA role and restart 
        lRetVal = sl_WlanSetMode(ROLE_STA);
        ASSERT_ON_ERROR(lRetVal);

        lRetVal = sl_Stop(0xFF);
        ASSERT_ON_ERROR(lRetVal);

        lRetVal = sl_Start(0, 0, 0);
        ASSERT_ON_ERROR(lRetVal);

        // Check if the device is in station again 
        if (ROLE_STA != lRetVal)
        {
            // We don't want to proceed if the device is not coming up in STA-mode 
            return DEVICE_NOT_IN_STATION_MODE;
        }
    }
    
    // Get the device's version-information
    ucConfigOpt = SL_DEVICE_GENERAL_VERSION;
    ucConfigLen = sizeof(ver);
    lRetVal = sl_DevGet(SL_DEVICE_GENERAL_CONFIGURATION, &ucConfigOpt, 
                                &ucConfigLen, (unsigned char *)(&ver));
    ASSERT_ON_ERROR(lRetVal);
    
    UART_PRINT("Host Driver Version: %s\n\r",SL_DRIVER_VERSION);
    UART_PRINT("Build Version %d.%d.%d.%d.31.%d.%d.%d.%d.%d.%d.%d.%d\n\r",
    ver.NwpVersion[0],ver.NwpVersion[1],ver.NwpVersion[2],ver.NwpVersion[3],
    ver.ChipFwAndPhyVersion.FwVersion[0],ver.ChipFwAndPhyVersion.FwVersion[1],
    ver.ChipFwAndPhyVersion.FwVersion[2],ver.ChipFwAndPhyVersion.FwVersion[3],
    ver.ChipFwAndPhyVersion.PhyVersion[0],ver.ChipFwAndPhyVersion.PhyVersion[1],
    ver.ChipFwAndPhyVersion.PhyVersion[2],ver.ChipFwAndPhyVersion.PhyVersion[3]);

    // Set connection policy to Auto + SmartConfig 
    //      (Device's default connection policy)
    lRetVal = sl_WlanPolicySet(SL_POLICY_CONNECTION, 
                                SL_CONNECTION_POLICY(1, 0, 0, 0, 1), NULL, 0);
    ASSERT_ON_ERROR(lRetVal);

    // Remove all profiles
    lRetVal = sl_WlanProfileDel(0xFF);
    ASSERT_ON_ERROR(lRetVal);

    

    //
    // Device in station-mode. Disconnect previous connection if any
    // The function returns 0 if 'Disconnected done', negative number if already
    // disconnected Wait for 'disconnection' event if 0 is returned, Ignore 
    // other return-codes
    //
    lRetVal = sl_WlanDisconnect();
    if(0 == lRetVal)
    {
        // Wait
        while(IS_CONNECTED(g_ulStatus))
        {
#ifndef SL_PLATFORM_MULTI_THREADED
              _SlNonOsMainLoopTask(); 
#endif
        }
    }

    // Enable DHCP client
    lRetVal = sl_NetCfgSet(SL_IPV4_STA_P2P_CL_DHCP_ENABLE,1,1,&ucVal);
    ASSERT_ON_ERROR(lRetVal);

    // Disable scan
    ucConfigOpt = SL_SCAN_POLICY(0);
    lRetVal = sl_WlanPolicySet(SL_POLICY_SCAN , ucConfigOpt, NULL, 0);
    ASSERT_ON_ERROR(lRetVal);

    // Set Tx power level for station mode
    // Number between 0-15, as dB offset from max power - 0 will set max power
    ucPower = 0;
    lRetVal = sl_WlanSet(SL_WLAN_CFG_GENERAL_PARAM_ID, 
            WLAN_GENERAL_PARAM_OPT_STA_TX_POWER, 1, (unsigned char *)&ucPower);
    ASSERT_ON_ERROR(lRetVal);

    // Set PM policy to normal
    lRetVal = sl_WlanPolicySet(SL_POLICY_PM , SL_NORMAL_POLICY, NULL, 0);
    ASSERT_ON_ERROR(lRetVal);

    // Unregister mDNS services
    lRetVal = sl_NetAppMDNSUnRegisterService(0, 0);
    ASSERT_ON_ERROR(lRetVal);

    // Remove  all 64 filters (8*8)
    memset(RxFilterIdMask.FilterIdMask, 0xFF, 8);
    lRetVal = sl_WlanRxFilterSet(SL_REMOVE_RX_FILTER, (_u8 *)&RxFilterIdMask,
                       sizeof(_WlanRxFilterOperationCommandBuff_t));
    ASSERT_ON_ERROR(lRetVal);

    lRetVal = sl_Stop(SL_STOP_TIMEOUT);
    ASSERT_ON_ERROR(lRetVal);

    InitializeAppVariables();
    
    return lRetVal; // Success
}


//*****************************************************************************
//
//! Board Initialization & Configuration
//!
//! \param  None
//!
//! \return None
//
//*****************************************************************************
static void BoardInit(void)
{
/* In case of TI-RTOS vector table is initialize by OS itself */
#ifndef USE_TIRTOS
  //
  // Set vector table base
  //
#if defined(ccs)
    MAP_IntVTableBaseSet((unsigned long)&g_pfnVectors[0]);
#endif
#if defined(ewarm)
    MAP_IntVTableBaseSet((unsigned long)&__vector_table);
#endif
#endif
    //
    // Enable Processor
    //
    MAP_IntMasterEnable();
    MAP_IntEnable(FAULT_SYSTICK);

    PRCMCC3200MCUInit();
}


//****************************************************************************
//
//! \brief Connecting to a WLAN Accesspoint
//!
//!  This function connects to the required AP (SSID_NAME) with Security
//!  parameters specified in te form of macros at the top of this file
//!
//! \param  None
//!
//! \return  0 on success else error code
//!
//! \warning    If the WLAN connection fails or we don't aquire an IP
//!            address, It will be stuck in this function forever.
//
//****************************************************************************
static long WlanConnect()
{
    SlSecParams_t secParams = {0};
    long lRetVal = 0;

    secParams.Key = SECURITY_KEY;
    secParams.KeyLen = strlen(SECURITY_KEY);
    secParams.Type = SECURITY_TYPE;

    lRetVal = sl_WlanConnect(SSID_NAME, strlen(SSID_NAME), 0, &secParams, 0);
    ASSERT_ON_ERROR(lRetVal);

    // Wait for WLAN Event
    while((!IS_CONNECTED(g_ulStatus)) || (!IS_IP_ACQUIRED(g_ulStatus)))
    {
        // Toggle LEDs to Indicate Connection Progress
        _SlNonOsMainLoopTask();
        GPIO_IF_LedOff(MCU_IP_ALLOC_IND);
        MAP_UtilsDelay(800000);
        _SlNonOsMainLoopTask();
        GPIO_IF_LedOn(MCU_IP_ALLOC_IND);
        MAP_UtilsDelay(800000);
    }

    return SUCCESS;

}

//*****************************************************************************
//
//! This function updates the date and time of CC3200.
//!
//! \param None
//!
//! \return
//!     0 for success, negative otherwise
//!
//*****************************************************************************

static int set_time()
{
    long retVal;

    g_time.tm_day = DATE;
    g_time.tm_mon = MONTH;
    g_time.tm_year = YEAR;
    g_time.tm_sec = HOUR;
    g_time.tm_hour = MINUTE;
    g_time.tm_min = SECOND;

    retVal = sl_DevSet(SL_DEVICE_GENERAL_CONFIGURATION,
                          SL_DEVICE_GENERAL_CONFIGURATION_DATE_TIME,
                          sizeof(SlDateTime),(unsigned char *)(&g_time));

    ASSERT_ON_ERROR(retVal);
    return SUCCESS;
}

//*****************************************************************************
//
//! This function demonstrates how certificate can be used with SSL.
//! The procedure includes the following steps:
//! 1) connect to an open AP
//! 2) get the server name via a DNS request
//! 3) define all socket options and point to the CA certificate
//! 4) connect to the server via TCP
//!
//! \param None
//!
//! \return  0 on success else error code
//! \return  LED1 is turned solid in case of success
//!    LED2 is turned solid in case of failure
//!
//*****************************************************************************
static int tls_connect()
{
    SlSockAddrIn_t    Addr;
    int    iAddrSize;
    unsigned char    ucMethod = SL_SO_SEC_METHOD_TLSV1_2;
    unsigned int uiIP,uiCipher = SL_SEC_MASK_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA;
    long lRetVal = -1;
    int iSockID;

    lRetVal = sl_NetAppDnsGetHostByName(g_Host, strlen((const char *)g_Host),
                                    (unsigned long*)&uiIP, SL_AF_INET);

    if(lRetVal < 0)
    {
        UART_PRINT("Device couldn't retrive the host name \n\r");
        GPIO_IF_LedOn(MCU_RED_LED_GPIO);
        return lRetVal;
    }

    Addr.sin_family = SL_AF_INET;
    Addr.sin_port = sl_Htons(GOOGLE_DST_PORT);
    Addr.sin_addr.s_addr = sl_Htonl(uiIP);
    iAddrSize = sizeof(SlSockAddrIn_t);
    //
    // opens a secure socket 
    //
    iSockID = sl_Socket(SL_AF_INET,SL_SOCK_STREAM, SL_SEC_SOCKET);
    if( iSockID < 0 )
    {
        UART_PRINT("Device unable to create secure socket \n\r");
        GPIO_IF_LedOn(MCU_RED_LED_GPIO);
        return lRetVal;
    }

    //
    // configure the socket as TLS1.2
    //
    lRetVal = sl_SetSockOpt(iSockID, SL_SOL_SOCKET, SL_SO_SECMETHOD, &ucMethod,\
                               sizeof(ucMethod));
    if(lRetVal < 0)
    {
        UART_PRINT("Device couldn't set socket options \n\r");
        GPIO_IF_LedOn(MCU_RED_LED_GPIO);
        return lRetVal;
    }
    //
    //configure the socket as ECDHE RSA WITH AES256 CBC SHA
    //
    lRetVal = sl_SetSockOpt(iSockID, SL_SOL_SOCKET, SL_SO_SECURE_MASK, &uiCipher,\
                           sizeof(uiCipher));
    if(lRetVal < 0)
    {
        UART_PRINT("Device couldn't set socket options \n\r");
        GPIO_IF_LedOn(MCU_RED_LED_GPIO);
        return lRetVal;
    }

    //
    //configure the socket with CA certificate - for server verification
    //
    lRetVal = sl_SetSockOpt(iSockID, SL_SOL_SOCKET, \
                           SL_SO_SECURE_FILES_CA_FILE_NAME, \
						   SL_SSL_CA_CERT, \
                           strlen(SL_SSL_CA_CERT));

    if(lRetVal < 0)
    {
        UART_PRINT("Device couldn't set socket options \n\r");
        GPIO_IF_LedOn(MCU_RED_LED_GPIO);
        return lRetVal;
    }

    //configure the socket with Client Certificate - for server verification
    //
    lRetVal = sl_SetSockOpt(iSockID, SL_SOL_SOCKET, \
    			SL_SO_SECURE_FILES_CERTIFICATE_FILE_NAME, \
									SL_SSL_CLIENT, \
                           strlen(SL_SSL_CLIENT));

    if(lRetVal < 0)
    {
        UART_PRINT("Device couldn't set socket options \n\r");
        GPIO_IF_LedOn(MCU_RED_LED_GPIO);
        return lRetVal;
    }

    //configure the socket with Private Key - for server verification
    //
    lRetVal = sl_SetSockOpt(iSockID, SL_SOL_SOCKET, \
    		SL_SO_SECURE_FILES_PRIVATE_KEY_FILE_NAME, \
			SL_SSL_PRIVATE, \
                           strlen(SL_SSL_PRIVATE));

    if(lRetVal < 0)
    {
        UART_PRINT("Device couldn't set socket options \n\r");
        GPIO_IF_LedOn(MCU_RED_LED_GPIO);
        return lRetVal;
    }


    /* connect to the peer device - Google server */
    lRetVal = sl_Connect(iSockID, ( SlSockAddr_t *)&Addr, iAddrSize);

    if(lRetVal < 0)
    {
        UART_PRINT("Device couldn't connect to AWS server \n\r");
        GPIO_IF_LedOn(MCU_RED_LED_GPIO);
        return lRetVal;
    }
    else{
    	UART_PRINT("Device has connected to the website:");
    	UART_PRINT(SERVER_NAME);
    	UART_PRINT("\n\r");
    }

    GPIO_IF_LedOff(MCU_RED_LED_GPIO);
    GPIO_IF_LedOn(MCU_GREEN_LED_GPIO);
    return iSockID;
}

int connectToAccessPoint(){
	long lRetVal = -1;
    GPIO_IF_LedConfigure(LED1|LED3);

    GPIO_IF_LedOff(MCU_RED_LED_GPIO);
    GPIO_IF_LedOff(MCU_GREEN_LED_GPIO);

    lRetVal = InitializeAppVariables();
    ASSERT_ON_ERROR(lRetVal);

    //
    // Following function configure the device to default state by cleaning
    // the persistent settings stored in NVMEM (viz. connection profiles &
    // policies, power policy etc)
    //
    // Applications may choose to skip this step if the developer is sure
    // that the device is in its default state at start of applicaton
    //
    // Note that all profiles and persistent settings that were done on the
    // device will be lost
    //
    lRetVal = ConfigureSimpleLinkToDefaultState();
    if(lRetVal < 0)
    {
      if (DEVICE_NOT_IN_STATION_MODE == lRetVal)
          UART_PRINT("Failed to configure the device in its default state \n\r");

      return lRetVal;
    }

    UART_PRINT("Device is configured in default state \n\r");

    CLR_STATUS_BIT_ALL(g_ulStatus);

    ///
    // Assumption is that the device is configured in station mode already
    // and it is in its default state
    //
    lRetVal = sl_Start(0, 0, 0);
    if (lRetVal < 0 || ROLE_STA != lRetVal)
    {
        UART_PRINT("Failed to start the device \n\r");
        return lRetVal;
    }

    UART_PRINT("Device started as STATION \n\r");

    //
    //Connecting to WLAN AP
    //
    lRetVal = WlanConnect();
    if(lRetVal < 0)
    {
        UART_PRINT("Failed to establish connection w/ an AP \n\r");
        GPIO_IF_LedOn(MCU_RED_LED_GPIO);
        return lRetVal;
    }

    UART_PRINT("Connection established w/ AP and IP is aquired \n\r");
    return 0;
}
void SPIInit(){
	// Reset SPI
	MAP_SPIReset(GSPI_BASE);

	//Enables the transmit and/or receive FIFOs.
	//Base address is GSPI_BASE, SPI_TX_FIFO || SPI_RX_FIFO are the FIFOs to be enabled
	MAP_SPIFIFOEnable(GSPI_BASE, SPI_TX_FIFO || SPI_RX_FIFO);

	// Configure SPI interface
	MAP_SPIConfigSetExpClk(GSPI_BASE,MAP_PRCMPeripheralClockGet(PRCM_GSPI),
					 SPI_IF_BIT_RATE,SPI_MODE_MASTER,SPI_SUB_MODE_0,
					 (SPI_SW_CTRL_CS |
					 SPI_4PIN_MODE |
					 SPI_TURBO_OFF |
					 SPI_CS_ACTIVELOW |
					 SPI_WL_8));

	// Enable SPI for communication
	MAP_SPIEnable(GSPI_BASE);
}

void sendMessage(char str[8], int retval){
	char str2[100];
	int i;
	for(i = 0; i < 8; i++){
		str2[i] = str[i];
	}
	//Disables UART interrupt while sending characters
	MAP_UARTIntDisable(UARTA1_BASE, UART_INT_RX | UART_INT_RT);
	str2[7] = '\0';
	http_post(retval, str2);
	//Enables UART interrupts
	MAP_UARTIntEnable(UARTA1_BASE, UART_INT_RX | UART_INT_RT);
}

void receiveMessage(){
	int i;
	unsigned long ulStatus;
	//Get status of UART interrupt
	ulStatus = MAP_UARTIntStatus(UARTA1_BASE, true);
	UARTIntClear(UARTA1_BASE, ulStatus );
	//Create a small delay to ensure that the hardware functions correctly
	MAP_UtilsDelay(80000);
	for(i = 0; i < 8; i++){
		//Get the character from UART1 register
		MessageRx[i] = MAP_UARTCharGet(UARTA1_BASE);
		MAP_UtilsDelay(80000);
		//Draw the received char on the OLED
		drawChar(6*i, 64, MessageRx[i], WHITE, BLACK, 0x01);
		MAP_UtilsDelay(80000);
	}

	UARTIntEnable(UARTA1_BASE, UART_INT_RX|UART_INT_RT);
}

void UART1IntInit(){
	//configure Uart
	MAP_UARTConfigSetExpClk(UARTA1_BASE, MAP_PRCMPeripheralClockGet(PRCM_UARTA1),
	            UART_BAUD_RATE, (UART_CONFIG_WLEN_8 | UART_CONFIG_STOP_ONE |
	            UART_CONFIG_PAR_NONE));
	UARTEnable(UARTA1_BASE);
	// Disable FIFO so RX interrupt triggers on any character
	MAP_UARTFIFODisable(UARTA1_BASE);
	// Set interrupt handlers
	MAP_UARTIntRegister(UARTA1_BASE,receiveMessage);
	// Clear any interrupts that may have been present
	MAP_UARTIntClear(UARTA1_BASE, UART_INT_RX);
	// Enable interrupt
	MAP_UARTIntEnable(UARTA1_BASE, UART_INT_RX|UART_INT_RT);
	UARTFIFOEnable(UARTA1_BASE);
}

void GPIOIntHandler(){
	//THis function is called when a button on the remote is pressed
	//Disables the GPIO interrupt
	GPIOIntDisable(GPIOA1_BASE, 0x10);
	//Enables Systick
	SysTickEnable();
}

void GPIOIntInit(){
	//Enables GPIO interrupt
    MAP_IntEnable(INT_GPIOA1);
    //Register GPIO interrup with the function GIOPIntHandler()
    GPIOIntRegister(GPIOA1_BASE, GPIOIntHandler);
    //Enables the GPIO interrupt
    GPIOIntEnable(GPIOA1_BASE, 0x10);
    //Set type to falling edge
    GPIOIntTypeSet(GPIOA1_BASE, 0x10, GPIO_FALLING_EDGE);
}

void SystickIntHandler(){
	//Samples the voltage on pin 3
	if (GPIOPinRead(GPIOA1_BASE, 0x10)){
		//modify the bitsequence using logic AND
		//Use bitwise operation here to save memory. Another option is to use an aray
		bitsequence = bitsequence | (1LL << (64-index));
	}
	//Increments the next index of the bit in bitsequence to be modified
	index++;
	//Clear the GPIO interrupt
	GPIOIntClear(GPIOA1_BASE, 0x10);
	//Enables the GPIO interrupt
	GPIOIntEnable(GPIOA1_BASE, 0x10);
	if(index == 60)
	{
		//If 60 bits have been written, it's time to check what number on the remote the bit sequence reprensent.
		SysTickDisable();
		GPIOIntDisable(GPIOA1_BASE, 0x10);
	}
}

void SystickIntInit(){
	//Enables Systick
	SysTickIntEnable();
	//Registers the Systick interrupt handler
	SysTickIntRegister(SystickIntHandler);
	//Set the countdown time to about .1 ms
	SysTickPeriodSet(90000);
}

void remote(int retval){

	bitsequence = 0;
	    //Index of the bits in the variable bitsequence to be modified
	    index = 0;
	    //Index of the Transmitting char array
	    int MsgTxIndex = 0;
	    //Initialize the value of previous char to 0
	    char PreviousChar = 0;
	    //Initilze the value of pevious number to 1. 1 is used be cause it does not represent any letters on the remote control.
	    char PreviousNum = 1;
	    //Initialize the transmitting arrays and receiving arrays to spaces
	    memset(MessageTx, ' ', 8);
	    memset(MessageRx, ' ', 8);
	    // Initailizing the board

	    //Sequence of 64 bit code represented in base 10
	    uint64_t one = 127238051012453696;
	    uint64_t two = 127238050878367040;
		uint64_t three = 127238051075237184;
		uint64_t four = 127238050811290944;
		uint64_t five = 127238051041715520;
		uint64_t six = 127238050907563328;
		uint64_t seven = 127238051089884480;
		uint64_t eight = 127238050777744704;
		uint64_t nine =127238051024946496;
		uint64_t zero = 127238050752931136;
		uint64_t delete1 =11385099857992613856;
		uint64_t delete2 =11529215046068469728;
		uint64_t mute =127238050886751552;
		Report("fillscreen\n\r");
		fillScreen(YELLOW);
		Report("fillscreen2\n\r");
		//fillScreen(BLACK);
	    while(1){
	        if(index == 60){
	        	//printf("%" PRIu64 "\n", bitsequence);
	        	if(bitsequence == one){
	        		Report("One\n\r");
	        		PreviousChar = 0;
	        		MsgTxIndex++;
	        	}else if(bitsequence == two){
	        		if(PreviousNum == 2){
	        			//If the same button is pressed, then modify the current character rather than moving on to the next index
	        			MsgTxIndex--;
	        		}
	        		switch(PreviousChar){
	        		case 'a':
	        			//If previous character is an a, then put b into the char array
	        			MessageTx[MsgTxIndex] = 'b';
	        			break;
	        		case 'b':
	        			//If previous character is an b, then put b into the char array
	        			MessageTx[MsgTxIndex] = 'c';
	        			break;
	        		default:
	        			//If previous character is anything other than a or b, then put a into the char array
	        			MessageTx[MsgTxIndex] = 'a';
	        			break;
	        		}
	        		//Set the previous num so that we will know what the previous number is in the next iteration of the while loop
	        		PreviousNum = 2;
	        		//Set the previous char so that we will know what the previous char is in the next iteration of the while loop
	        		//Increments the index value
	        		PreviousChar = MessageTx[MsgTxIndex++];
	        		Report("Two\n\r");
	        	}else if(bitsequence == three){
	        		if(PreviousNum == 3){
	        			MsgTxIndex--;
	        		}
	        		switch(PreviousChar){
	        		case 'e':
	        			MessageTx[MsgTxIndex] = 'f';
	        			break;
	        		case 'f':
	        			MessageTx[MsgTxIndex] = 'd';
	        			break;
	        		default:
	        			MessageTx[MsgTxIndex] = 'e';
	        			break;
	        		}
	        		PreviousNum = 3;
	        		PreviousChar = MessageTx[MsgTxIndex++];
	        		Report("Three\n\r");
	        	}else if(bitsequence == four){
	        		if(PreviousNum == 4){
	        			MsgTxIndex--;
	        		}
	        		switch(PreviousChar){
	        		case 'g':
	        			MessageTx[MsgTxIndex] = 'h';
	        			break;
	        		case 'h':
	        			MessageTx[MsgTxIndex] = 'i';
	        			break;
	        		default:
	        			MessageTx[MsgTxIndex] = 'g';
	        			break;
	        		}
	        		PreviousNum = 4;
	        		PreviousChar = MessageTx[MsgTxIndex++];
	        		Report("Four\n\r");
	        	}else if(bitsequence == five){
	        		if(PreviousNum == 5){
	        			MsgTxIndex--;
	        		}
	        		switch(PreviousChar){
	        		case 'j':
	        			MessageTx[MsgTxIndex] = 'k';
	        			break;
	        		case 'k':
	        			MessageTx[MsgTxIndex] = 'l';
	        			break;
	        		default:
	        			MessageTx[MsgTxIndex] = 'j';
	        			break;
	        		}
	        		PreviousNum = 5;
	        		PreviousChar = MessageTx[MsgTxIndex++];
	        		Report("Five\n\r");
	        	}else if(bitsequence == six){
	        		if(PreviousNum == 6){
	        			MsgTxIndex--;
	        		}
	        		switch(PreviousChar){
	        		case 'm':
	        			MessageTx[MsgTxIndex] = 'n';
	        			break;
	        		case 'n':
	        			MessageTx[MsgTxIndex] = 'o';
	        			break;
	        		default:
	        			MessageTx[MsgTxIndex] = 'm';
	        			break;
	        		}
	        		PreviousNum = 6;
	        		PreviousChar = MessageTx[MsgTxIndex++];
	        		Report("Six\n\r");
	        	}else if(bitsequence == seven){
	        		printf("seven\n");
	        		if(PreviousNum == 7){
	        			MsgTxIndex--;
	        		}
	        		switch(PreviousChar){
	        		case 'p':
	        			MessageTx[MsgTxIndex] = 'q';
	        			break;
	        		case 'q':
	        			MessageTx[MsgTxIndex] = 'r';
	        			break;
	        		case 'r':
	        			MessageTx[MsgTxIndex] = 's';
	        			break;
	        		default:
	        			MessageTx[MsgTxIndex] = 'p';
	        			break;
	        		}
	        		PreviousNum = 7;
	        		PreviousChar = MessageTx[MsgTxIndex++];
	        		Report("Seven\n\r");
	        	}else if(bitsequence == eight){
	        		if(PreviousNum == 8){
	        			MsgTxIndex--;
	        		}
	        		switch(PreviousChar){
	        		case 't':
	        			MessageTx[MsgTxIndex] = 'u';
	        			break;
	        		case 'u':
	        			MessageTx[MsgTxIndex] = 'v';
	        			break;
	        		default:
	        			MessageTx[MsgTxIndex] = 't';
	        			break;
	        		}
	        		PreviousNum = 8;
	        		PreviousChar = MessageTx[MsgTxIndex++];
	        		Report("Eight\n\r");
	        	}else if(bitsequence == nine){
	        		if(PreviousNum == 9){
	        			MsgTxIndex--;
	        		}
	        		switch(PreviousChar){
	        		case 'w':
	        			MessageTx[MsgTxIndex] = 'x';
	        			break;
	        		case 'x':
	        			MessageTx[MsgTxIndex] = 'y';
	        			break;
	        		case 'y':
	        			MessageTx[MsgTxIndex] = 'z';
	        			break;
	        		default:
	        			MessageTx[MsgTxIndex] = 'w';
	        			break;
	        		}
	        		PreviousNum = 9;
	        		PreviousChar = MessageTx[MsgTxIndex++];
	        		Report("Nine\n\r");
	        	}else if(bitsequence == zero){
	        		MessageTx[MsgTxIndex] = ' ';
	        		PreviousNum = 0;
	        		PreviousChar = MessageTx[MsgTxIndex++];
	        		Report("Zero\n\r");
	        	}else if (bitsequence == delete1 || bitsequence == delete2){
	        		MessageTx[MsgTxIndex--] = ' ';
	        		MessageTx[MsgTxIndex] = ' ';
	        		Report("Delete\n\r");
	        	}else if (bitsequence == mute){
	        		Report("Mute\n\r");
	        		//if the button is mute, then we send the message array to the UART
	        		//sendMessage(retval, MessageTx);
	        		sendMessage(MessageTx, retval);
	        	}

	        	//draw the entered characters on the OLED
	        	int i = 0;
	        	for(i = 0; i < 8; i++){
	        		drawChar(6*i, 0, MessageTx[i], WHITE, BLACK, 0x01);
	        	}
	    		index = 0;
	    		//reset the bit sequence in order to capture the next bit ssequence
	    		bitsequence = 0;
	    		GPIOIntEnable(GPIOA1_BASE, 0x10);
	        }
	    }
}



//*****************************************************************************
//
//! Main 
//!
//! \param  none
//!
//! \return None
//!
//*****************************************************************************
void main()
{
    long lRetVal = -1;
    //
    // Initialize board configuration
    //
    BoardInit();

    PinMuxConfig();
    //Initialize GPIO interrupt
    GPIOIntInit();
    //Initialize Systick interrupt
    SystickIntInit();
    //Initialize Uart interrupt
    UART1IntInit();
    //Initialize SPI
    SPIInit();
    //Initalize Adafruit
    Adafruit_Init();

    InitTerm();
    //Connect the CC3200 to the local access point
    lRetVal = connectToAccessPoint();
    //Set time so that encryption can be used
    lRetVal = set_time();
    if(lRetVal < 0)
    {
        UART_PRINT("Unable to set time in the device");
        LOOP_FOREVER();
    }
    //Connect to the website with TLS encryption
    lRetVal = tls_connect();
    if(lRetVal < 0)
    {
        ERR_PRINT(lRetVal);
    }

    //remote calls sendMessage() which calls http_post() which requires the return value from tls_connect()
    remote(lRetVal);

    //http_post(lRetVal);

    sl_Stop(SL_STOP_TIMEOUT);
    LOOP_FOREVER();
}
//*****************************************************************************
//
// Close the Doxygen group.
//! @}
//
//*****************************************************************************

static int http_post(int iTLSSockID, char data[200]){
    char acSendBuff[512];
    char acRecvbuff[1460];
    char cCLLength[200];
    char* pcBufHeaders;
    int lRetVal = 0;

	pcBufHeaders = acSendBuff;
	strcpy(pcBufHeaders, POSTHEADER);
	pcBufHeaders += strlen(POSTHEADER);
	strcpy(pcBufHeaders, " HTTP/1.1\r\n");
	pcBufHeaders += strlen(" HTTP/1.1\r\n");
	strcpy(pcBufHeaders, HOSTHEADER);
	pcBufHeaders += strlen(HOSTHEADER);

	//
	strcpy(pcBufHeaders, CHEADER0);
	pcBufHeaders += strlen(CHEADER0);
	//

	strcpy(pcBufHeaders, CHEADER);
	pcBufHeaders += strlen(CHEADER);
	strcpy(pcBufHeaders, "\r\n\r\n");
  //calculates the length of the message, DATA1 + text message + DATA2
	int dataLength = strlen(DATA1);
	dataLength += strlen(data);
	dataLength += strlen(DATA3);
	strcpy(pcBufHeaders, CTHEADER);
	pcBufHeaders += strlen(CTHEADER);
	strcpy(pcBufHeaders, CLHEADER1);

	pcBufHeaders += strlen(CLHEADER1);
	sprintf(cCLLength, "%d", dataLength);

	strcpy(pcBufHeaders, cCLLength);
	pcBufHeaders += strlen(cCLLength);
	strcpy(pcBufHeaders, CLHEADER2);
	pcBufHeaders += strlen(CLHEADER2);

	strcpy(pcBufHeaders, DATA1);
	pcBufHeaders += strlen(DATA1);

	strcpy(pcBufHeaders, data);
	pcBufHeaders += strlen(data);

	strcpy(pcBufHeaders, DATA3);
	pcBufHeaders += strlen(DATA3);

	int testDataLength = strlen(pcBufHeaders);

	//
	// Send the packet to the server */
	//

	printf("%s\n", acSendBuff);

	lRetVal = sl_Send(iTLSSockID, acSendBuff, strlen(acSendBuff), 0);
	if(lRetVal < 0)
	{
		UART_PRINT("POST failed. Error Number: %i\n\r",lRetVal);
    	sl_Close(iTLSSockID);
    	GPIO_IF_LedOn(MCU_RED_LED_GPIO);
    	return lRetVal;
	}
	lRetVal = sl_Recv(iTLSSockID, &acRecvbuff[0], sizeof(acRecvbuff), 0);
	if(lRetVal < 0)
	{
		UART_PRINT("Received failed. Error Number: %i\n\r",lRetVal);
	    //sl_Close(iSSLSockID);
	    GPIO_IF_LedOn(MCU_RED_LED_GPIO);
	       return lRetVal;
	}
	else
	{
		acRecvbuff[lRetVal+1] = '\0';
		UART_PRINT(acRecvbuff);
		UART_PRINT("\n\r\n\r");
	}

	return 0;
}
