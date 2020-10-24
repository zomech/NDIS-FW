
/**
	TODO:
	add protocol (tcp\udp) in options

**/

#include <stdlib.h>
#include <stdio.h>
#include <Windows.h>


#define _NDIS_CONTROL_CODE(request,method) \
            CTL_CODE(FILE_DEVICE_PHYSICAL_NETCARD, request, method, FILE_ANY_ACCESS)

#define IOCTL_FILTER_FW_UPDATE_POLICY  _NDIS_CONTROL_CODE(200, METHOD_BUFFERED)
#define IOCTL_FILTER_FW_SHOW_POLICY  _NDIS_CONTROL_CODE(201, METHOD_BUFFERED)

typedef enum {

	FWAction_Drop,
	FWAction_Allow,
	FWAction_Modify

}FWRule_Action, * PFWRule_Action;

typedef enum {

	FWPolicy_Incoming,
	FWPolicy_Outgoing

}FW_Policy_Type, * PFW_Policy_Type;

typedef struct {

	char action;           // FWRule_Action enum
	char protocol;         // IPPROTO enum
	char ip_str[16];
	short port;
	//char* modify_data;


}FW_Incoming_Rule, * PFW_Incoming_Rule;

typedef struct {

	char policy;
	char action; // update action - remove rule\ add rule
	FW_Incoming_Rule rule;

}FW_Incoming_Rule_Update, * PFW_Incoming_Rule_Update;

typedef enum {

	FWRule_Delete, // Delete rule from policy
	FWRule_Append, // Append rule to policy
	FWRule_Modify  // Modify rule from policy - in development

}FW_Policy_Action, * PFW_Policy_Action;

typedef struct {

	unsigned long long rules_count;
	FW_Incoming_Rule_Update rules_info[1];

}FW_Incoming_Policy_Update, * PFW_Incoming_Policy_Update;

typedef struct FWCONTROL {

	char policy;
	short port;
	char ip_addr[16];
	char policy_action;
	char rule_action;

}FWCONTROL_OPTIONS, * PFWCONTROL_OPTIONS;

typedef struct {

	unsigned long long rules_count;
	FW_Incoming_Rule rules[1];

}IncomingFirewall, * PIncomingFirewall;


void print_help()
{
	printf("\nHelp Menu\n\n");
	printf("Options:\n");
	printf("\tadd\t\tAdd a rule to a specific fw policy, use with all mandatory prarameters\n");
	printf("\tremove\t\tRemoves a rule to a specific fw policy, use with all mandatory prarameters\n");
	printf("\tshow\t\tShows a list of all the rules of a specified fw policy\n");
	printf("\n\nParameters:\n");
	printf("\tMandatory for all options:\n");
	printf("\t-policy\t\tThe Firewall Policy to update\\view\n\t\t\toptions: <incoming> <outgoing> <both>(only for showing firewall rules - not updating)\n\n");
	printf("\tMandatory for add and remove options:\n");
	printf("\t-ip\t\tThe ip address, can be used with wildcards characters (?, *)\n");
	printf("\t-port\t\tThe source or destination port of the packet\n");
	printf("\t-action\t\tWhat to do with the packet - options are <drop> <allow> <modify>(in development)\n\n");

}


void print_fw(BYTE* buf, char policy)
{

	if (policy == FWPolicy_Incoming)
	{
		printf("\n\n------------------Incoming Firewall------------------\n\n");
		printf(" ID    Src Ip Address    Port    Protocol    Action\n\n\n");
	}
	else if (policy == FWPolicy_Outgoing)
	{
		printf("\n\n------------------Outgoing Firewall------------------\n\n");
		printf(" ID    Dst Ip Address    Port    Protocol    Action\n\n\n");
	}

	IncomingFirewall* incoming_fw = (IncomingFirewall*)buf;

	char* drop = "drop";
	char* allow = "allow";
	char* modify = "modify";
	char* tcp = "tcp";
	char* udp = "udp";

	char* action = 0;
	char* protocol = 0;

	//printf(" ID  Ip Address        Port    Protocol    Action\n\n\n");

	for (int i = 0; i < incoming_fw->rules_count; i++)
	{

		if (incoming_fw->rules[i].action == FWAction_Drop)
		{
			action = drop;
		}
		else if (incoming_fw->rules[i].action == FWAction_Allow)
		{
			action = allow;
		}
		else if (incoming_fw->rules[i].action == FWAction_Modify)
		{
			action = modify;
		}

		if (incoming_fw->rules[i].protocol == IPPROTO_TCP)
		{
			protocol = tcp;
		}
		else if (incoming_fw->rules[i].protocol == IPPROTO_UDP)
		{
			protocol = udp;
		}

		printf(" %-6d%-18s%-8d%-12s%-6s\n\n", i + 1, incoming_fw->rules[i].ip_str, incoming_fw->rules[i].port, protocol, action);

		action = 0;
		protocol = 0;
	}
}

BOOL parse_arguments(int argc, char* argv[], FWCONTROL_OPTIONS* options) {

	BOOL ret = FALSE;

	if (_stricmp(argv[1], "add") == 0)
	{
		options->policy_action = FWRule_Append;
	}

	else if (_stricmp(argv[1], "delete") == 0)
	{
		options->policy_action = FWRule_Delete;
	}

	else if (_stricmp(argv[1], "modify") == 0)
	{
		options->policy_action = FWRule_Modify;
	}

	else if (_stricmp(argv[1], "show") == 0)
	{
		options->policy_action = 3;
	}
	else
	{
		printf("%s parameter not found\n", argv[1]);
		return ret;
	}


	for (int i = 2; i < argc; i++) {

		if (_stricmp(argv[i], "-policy") == 0)
		{

			if (_stricmp(argv[i + 1], "incoming") == 0)
			{
				options->policy = FWPolicy_Incoming;
			}

			else if (_stricmp(argv[i + 1], "outgoing") == 0)
			{
				options->policy = FWPolicy_Outgoing;
			}

			else if (_stricmp(argv[i + 1], "both") == 0)
			{
				options->policy = 2;

			}

			if (options->policy_action == 3)
			{
				i = argc;
			}
			else
			{
				i++;
			}
		}

		else if (_stricmp(argv[i], "-ip") == 0)
		{
			memcpy(options->ip_addr, argv[i + 1], 16);

			i++;
		}

		else if (_stricmp(argv[i], "-port") == 0)
		{
			options->port = atoi(argv[i + 1]);

			i++;
		}

		else if (_stricmp(argv[i], "-action") == 0)
		{

			if (_stricmp(argv[i + 1], "allow") == 0)
			{
				options->rule_action = FWAction_Allow;
			}

			else if (_stricmp(argv[i + 1], "drop") == 0)
			{
				options->rule_action = FWAction_Drop;
			}

			else if (_stricmp(argv[i + 1], "modify") == 0)
			{
				options->rule_action = FWAction_Modify;
			}

			i++;
		}

		else
		{
			printf("%s parameter not found\n", argv[i]);
		}
	}

	// Show rules
	if (options->policy_action == 3 && (options->policy == 0 || options->policy == 1 || options->policy == 2))
	{
		ret = TRUE;
	}

	// Add/Remove rules
	else if (options->port != 0 && *(options->ip_addr) != 0 && options->policy_action != -1 && options->policy != -1 && options->rule_action != -1)
	{
		ret = TRUE;
	}

	return ret;
}

int main(int argc, char* argv[]) {

	FWCONTROL_OPTIONS options = { 0 };
	options.policy_action = -1;
	options.rule_action = -1;
	options.policy = -1;

	if (argc <= 1)
	{
		printf("\nNot enough parameters\n");
		print_help();
		return 1;
	}

	BOOL ok = parse_arguments(argc, argv, &options);

	if (!ok) {

		printf("\nIncorrect parameters\n");
		print_help();
		return 1;
	}

	FW_Incoming_Policy_Update fw_update = { 0 };
	fw_update.rules_count = 1;

	DWORD fw_update_size = (sizeof(FW_Incoming_Policy_Update) + (fw_update.rules_count * sizeof(FW_Incoming_Rule_Update)));
	HANDLE hDevice = INVALID_HANDLE_VALUE;
	BOOL success = TRUE;
	DWORD out = 0;

	char msg[100] = { 0 };
	BYTE* fw = 0;
	DWORD fw_size = 0;
	int substructor = 2;

	hDevice = CreateFileW(L"\\\\.\\ndislwf1", 0, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, 0);

	if (hDevice == INVALID_HANDLE_VALUE)
	{
		printf("Unable to open device - Error 0x%x\n", GetLastError());
		return 1;
	}

	// Show rules
	if (options.policy_action == 3)
	{

		// Will print both firewalls
		if (options.policy == 2)
		{
			substructor = 1;
			options.policy = 1;
		}


		while (options.policy >= 0)
		{

			success = DeviceIoControl(hDevice, IOCTL_FILTER_FW_SHOW_POLICY, &options.policy, sizeof(char), &fw_size, sizeof(fw_size), &out, NULL);

			if (success)
			{
				fw = (BYTE*)malloc(fw_size);
				success = DeviceIoControl(hDevice, IOCTL_FILTER_FW_SHOW_POLICY, &options.policy, sizeof(char), fw, fw_size, &out, NULL);
			}
			if (success)
			{
				print_fw(fw, options.policy);
			}
			else
			{
				printf("Error 0x%x\n", GetLastError());
				return 1;
			}


			free(fw);
			options.policy -= substructor;
		}


	}

	// Add\remove\modify rule
	else if ((options.policy_action == FWRule_Append || options.policy_action == FWRule_Delete || options.policy_action == FWRule_Modify)
		&& (options.policy == FWPolicy_Incoming || options.policy == FWPolicy_Outgoing))
	{
		fw_update.rules_info[0].action = options.policy_action;
		fw_update.rules_info[0].policy = options.policy;
		fw_update.rules_info[0].rule.action = options.rule_action;
		fw_update.rules_info[0].rule.port = options.port;
		fw_update.rules_info[0].rule.protocol = IPPROTO_TCP;
		memcpy(fw_update.rules_info[0].rule.ip_str, options.ip_addr, 16);

		success = DeviceIoControl(hDevice, IOCTL_FILTER_FW_UPDATE_POLICY, &fw_update, fw_update_size, NULL, 0, &out, NULL);

		if (success == FALSE)
		{
			if (GetLastError() == 0x490 && options.policy_action == FWRule_Append)
			{
				printf("Error - Rule Already exists\n");
			}
			else if (GetLastError() == 0x490 && options.policy_action == FWRule_Delete)
			{
				printf("Rule wasn't found\n");
			}
			else if (GetLastError() == 0x3)
			{
				printf("DB file wasn't found - Rules weren't saved to the db file\n");
			}
			else
			{
				printf("Error - 0x%x\n", GetLastError());
			}
		}
	}

	else
	{
		printf("Error - add\\delete\\modify or -policy parameter is incorrect\n");
	}


	return 0;
}