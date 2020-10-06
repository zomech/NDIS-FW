

#define incoming_fw_db_filename L"\\??\\C:\\Program Files\\NDIS Firewall\\in.fw"
#define outgoing_fw_db_filename L"\\??\\C:\\Program Files\\NDIS Firewall\\out.fw"
#define DB_DIRECTORY_NAME L"\\??\\C:\\Program Files\\NDIS Firewall\\"

#define htons(n) ( (((n) & 0xFF00) >> 8) | (((n) & 0x00FF) << 8) )
#define ntohs(n) ( (((n) & 0xFF00) >> 8) | (((n) & 0x00FF) << 8) )

typedef struct {
	char mac_dest[6];
	char mac_src[6];
	short ether_type;
} eth_header_t, * p_eth_header_t;

typedef struct {
	char header_len : 4, version : 4;
	char tos;
	short len;
	short id;
	short off;
	char ttl;
	char proto;
	short chksum;
	unsigned int src_addr;
	unsigned int dst_addr;
}ipv4_header, * p_ipv4_header;



typedef struct tcp_header
{
	unsigned short source_port; // source port
	unsigned short dest_port; // destination port
	unsigned int sequence; // sequence number - 32 bits
	unsigned int acknowledge; // acknowledgement number - 32 bits

	unsigned char ns : 1; //Nonce Sum Flag Added in RFC 3540.
	unsigned char reserved_part1 : 3; //according to rfc
	unsigned char data_offset : 4; /*The number of 32-bit words in the TCP header.
	This indicates where the data begins.
	The length of the TCP header is always a multiple
	of 32 bits.*/

	unsigned char fin : 1; //Finish Flag
	unsigned char syn : 1; //Synchronise Flag
	unsigned char rst : 1; //Reset Flag
	unsigned char psh : 1; //Push Flag
	unsigned char ack : 1; //Acknowledgement Flag
	unsigned char urg : 1; //Urgent Flag

	unsigned char ecn : 1; //ECN-Echo Flag
	unsigned char cwr : 1; //Congestion Window Reduced Flag

	////////////////////////////////

	unsigned short window; // window
	unsigned short checksum; // checksum
	unsigned short urgent_pointer; // urgent pointer
} tcp_header, * ptcp_header;

typedef enum {

	FWAction_Drop,
	FWAction_Allow,
	FWAction_Modify

}FWRule_Action, * PFWRule_Action;

typedef struct {

	char action;           // FW_action enum
	char protocol;         // IPPROTO enum
	char ip_str[16];
	short dst_port;
	//char* modify_data;


}FW_Rule, *PFW_Rule;

typedef FW_Rule FW_Incoming_Rule, FW_Outgoing_Rule;

// Action on Fw policies - add\delete\modify rules
typedef enum {

	FWRule_Delete,
	FWRule_Append,
	FWRule_Modify

}FW_Policy_Action, * PFW_Policy_Action;

typedef enum {

	FWPolicy_Incoming,
	FWPolicy_Outgoing

}FW_Policy_Type, * PFW_Policy_Type;

typedef struct {

	//FW_Policy_Type policy;
	char policy;
	//FW_Rule_Action action;
	char action;
	FW_Incoming_Rule rule;

}FW_Rule_Update_Info, *PFW_Rule_Update_Info;

typedef struct {

	size_t/*unsigned long long*/ rules_count;
	FW_Rule_Update_Info rules_info[1];

}FW_Policy_Update_Info, *PFW_Policy_Update_Info;


typedef struct {

	size_t/*unsigned long long*/ rules_count;
	FW_Incoming_Rule rules[1];

}Firewall, *PFirewall;

typedef Firewall IncomingFirewall, OutgoingFirewall;


NTSTATUS FilterIncomingPackets(unsigned char* buffer, unsigned int buffer_size);
NTSTATUS FilterOutgoingPackets(unsigned char* buffer, unsigned int buffer_size);
void inet_ntop(unsigned int ip, char* ip_str_buf, unsigned int ip_str_buf_size);
NTSTATUS UpdateFWRules(char*);
NTSTATUS LoadFWRules(wchar_t*, int mode);
NTSTATUS SaveFWRules(wchar_t*, int mode);
size_t GetFwSize(char policy);
void* GetIncomingFW();
void* GetOutgoingFW();
void CreateFWDataDir();