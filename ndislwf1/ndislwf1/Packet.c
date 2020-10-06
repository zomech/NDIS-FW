/*
	Written By Ziv Somech
*/
#include "precomp.h"

IncomingFirewall* incoming_fw = 0;
OutgoingFirewall* outgoing_fw = 0;
HANDLE incoming_file = 0;
HANDLE outgoing_file = 0;

// Creatinf directory in Program Files to store the db rules files
void CreateFWDataDir()
{
	NTSTATUS status;

	HANDLE hDir = NULL;
	IO_STATUS_BLOCK io;
	OBJECT_ATTRIBUTES object_att;
	UNICODE_STRING dir_name;

	RtlInitUnicodeString(&dir_name, DB_DIRECTORY_NAME);

	InitializeObjectAttributes(&object_att, &dir_name, (OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE), NULL, NULL);

	status = ZwCreateFile(&hDir, GENERIC_READ, &object_att, &io, NULL, FILE_ATTRIBUTE_DIRECTORY, FILE_SHARE_READ | FILE_SHARE_WRITE, 
		FILE_OPEN_IF, FILE_DIRECTORY_FILE, NULL, 0);
	
	if (hDir != NULL)
	{
		ZwClose(hDir);
	}
}

// calculate packet checksum, the checksum value is not included so if there is a current checksum we will subtruct it,
// meaning if we are modifing a packet we want to subtruct the current exsisting checksum with a new calculated checksum
unsigned short my_checksum(unsigned short* buf, unsigned int len, unsigned int src_addr, unsigned int dest_addr, unsigned short current_checksum)
{
	unsigned int sum = 0;
	int len2 = len;
	unsigned short* ip_src = (void*)&src_addr;
	unsigned short* ip_dst = (void*)&dest_addr;
	unsigned short* buffer = buf;

	while (len2 > 1)
	{
		sum += *buffer;
		buffer++;
		len2 -= 2;
	}

	if (len2 == 1)
	{
		sum += *(char*)buffer;
	}

	sum += *(unsigned short*)ip_src;
	ip_src++;
	sum += *(unsigned short*)ip_src;
	sum += *(unsigned short*)ip_dst;
	ip_dst++;
	sum += *(unsigned short*)ip_dst;
	sum += htons(len);
	sum += htons(IPPROTO_TCP);

	sum -= current_checksum;

	while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);

	return (unsigned short)~sum;

}



/*
BOOLEAN match(char* first, char* second)
{
	// If we reach at the end of both strings, we are done
	if (*first == '\0' && *second == '\0')
		return TRUE;

	// Make sure that the characters after '*' are present
	// in second string. This function assumes that the first
	// string will not contain two consecutive '*'
	if (*first == '*' && *(first + 1) != '\0' && *second == '\0')
		return FALSE;

	// If the first string contains '?', or current characters
	// of both strings match
	if (*first == '?' || *first == *second)
		return match(first + 1, second + 1);

	// If there is *, then there are two possibilities
	// a) We consider current character of second string
	// b) We ignore current character of second string.
	if (*first == '*')
		return match(first + 1, second) || match(first, second + 1);
	return FALSE;
}*/

// String comparison with wildcards
BOOLEAN strmatch(char* first, char* second)
{
	BOOLEAN cont = TRUE;

	size_t first_len = strlen(first);
	size_t second_len = strlen(second);
	int i = 0;;
	int j = 0;

	while (i < first_len && j < second_len && cont)
	{
		cont = FALSE;

		if (first[i] == '*' && first[i + 1] != '\0' && second[j] == '\0')
		{
			cont = FALSE;
		}

		else if (first[i] == '?' || first[i] == second[j])
		{
			cont = TRUE;
			i++;
			j++;
		}

		else if (first[i] == '*')
		{

			cont = TRUE;
			while (first[i + 1] != second[j] && second[j] != '\0')
			{
				j++;
			}
			i++;
		}
	}

	return (first[i] == '\0' && second[j] == '\0');
}




// Finds first occurrence of needle in haystack
void* memmem(const void* haystack, size_t haystack_len, const void* needle, size_t needle_len)
{
	const char* begin;
	const char* const last_possible
		= (const char*)haystack + haystack_len - needle_len;

	if (needle_len == 0)
		/* The first occurrence of the empty string is deemed to occur at
		   the beginning of the string.  */
		return (void*)haystack;

	/* Sanity check, otherwise the loop might search through the whole
	   memory.  */
	if (haystack_len < needle_len)
		return NULL;

	for (begin = (const char*)haystack; begin <= last_possible; ++begin)
		if (begin[0] == ((const char*)needle)[0] && !memcmp((const void*)&begin[1], (const void*)((const char*)needle + 1), needle_len - 1))
			return (void*)begin;

	return NULL;
}




// ip value to ip str
void inet_ntop(unsigned int ip, char* ip_str_buf, unsigned int ip_str_buf_size)
{
	ip = RtlUlongByteSwap(ip);
	unsigned char bytes[4];
	bytes[0] = ip & 0xFF;
	bytes[1] = (ip >> 8) & 0xFF;
	bytes[2] = (ip >> 16) & 0xFF;
	bytes[3] = (ip >> 24) & 0xFF;
	_snprintf_s(ip_str_buf, ip_str_buf_size, ip_str_buf_size, "%d.%d.%d.%d", bytes[3], bytes[2], bytes[1], bytes[0]);
}




// Saving the FW rules to a db file
NTSTATUS SaveFWRules(wchar_t* filename, int mode)
{
	NTSTATUS status = -1;
	IncomingFirewall* fw = 0;
	HANDLE* hFile = 0;

	// What policy to save
	if (mode == 1)
	{
		fw = incoming_fw;
		hFile = &incoming_file;
	}
	else if (mode == 2)
	{
		fw = outgoing_fw;
		hFile = &outgoing_file;
	}

	if (filename && fw)
	{
		//HANDLE hFile = 0;
		//LARGE_INTEGER file_offset = { 0 };
		OBJECT_ATTRIBUTES obj = { 0 };
		UNICODE_STRING file_str = { 0 };
		IO_STATUS_BLOCK isb = { 0 };
		unsigned long long struct_size = 0;

		// If we have a handle to the db file we close it to override the file with the updated data
		if (*hFile != NULL)
		{
			ZwClose(*hFile);
		}

		RtlInitUnicodeString(&file_str, filename);
		obj.Length = sizeof(OBJECT_ATTRIBUTES);
		obj.Attributes = OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE;
		obj.ObjectName = &file_str;

		status = ZwCreateFile(hFile, FILE_GENERIC_READ | FILE_GENERIC_WRITE, &obj, &isb, NULL, FILE_ATTRIBUTE_NORMAL, 0, FILE_OVERWRITE_IF,
			FILE_RANDOM_ACCESS | FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);


		// Creating the file succeeded or we we already have a handle to the file
		if (NT_SUCCESS(status) /*|| hFile*/)
		{
			
			struct_size = (sizeof(IncomingFirewall) + ((fw->rules_count) * sizeof(FW_Incoming_Rule)));
			status = ZwWriteFile(*hFile, NULL, NULL, NULL, &isb, fw, (unsigned long)struct_size, /*&file_offset*/NULL, NULL);
		}
	}

	return status;
}




// Loading FW rules from db file, if exists in the fw directory
NTSTATUS LoadFWRules(wchar_t* filename, int mode)
{

	NTSTATUS status = -1;
	IncomingFirewall* fw = 0;
	HANDLE hFile = 0;
	//DbgBreakPoint();


	if (filename)
	{
		//hFile = 0;
		OBJECT_ATTRIBUTES obj = { 0 };
		UNICODE_STRING file_str = { 0 };
		IO_STATUS_BLOCK isb = { 0 };
		ULONG file_size = 0;
		FILE_STANDARD_INFORMATION fsi = { 0 };
		//char* data = 0;

		RtlInitUnicodeString(&file_str, filename);
		obj.Length = sizeof(OBJECT_ATTRIBUTES);
		obj.Attributes = OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE;
		obj.ObjectName = &file_str;

		status = ZwCreateFile(&hFile, FILE_GENERIC_READ | FILE_GENERIC_WRITE, &obj, &isb, NULL, FILE_ATTRIBUTE_NORMAL, 0, FILE_OPEN_IF,
			FILE_RANDOM_ACCESS | FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);

		// Opened or created the db file
		if (NT_SUCCESS(status))
		{

			// Getting saved fw size
			status = ZwQueryInformationFile(hFile, &isb, &fsi, sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation);

			file_size = fsi.EndOfFile.LowPart;

			// If there is data in the db file we load it
			if (file_size > 0)
			{
				fw = ExAllocatePoolWithTag(PagedPool, (size_t)file_size + 1, 'WFSZ');
				if (fw)
				{
					memset(fw, 0, file_size);
				}
			}
			/*else
			{
				//fw = ExAllocatePoolWithTag(PagedPool, sizeof(IncomingFirewall), 'WFSZ');
				//memset(fw, 0, sizeof(IncomingFirewall));
			}*/

		}

		// succeeded in allocating space for the fw
		if (fw)
		{

			status = ZwReadFile(hFile, NULL, NULL, NULL, &isb, fw, file_size, 0, NULL);
			//ZwClose(hFile);
		}

		// if the db file is empty we allocate an empty fw struct
		else
		{
			fw = ExAllocatePoolWithTag(PagedPool, sizeof(IncomingFirewall), 'WFSZ');
			if (fw)
			{
				memset(fw, 0, sizeof(IncomingFirewall));
			}
		}

	}

	// saving the fw struct to the global pointers accourding to mode
	if (mode == 1)
	{
		//fw = incoming_fw;
		incoming_fw = fw;
		incoming_file = hFile;
	}
	else if (mode == 2)
	{
		//fw = outgoing_fw;
		outgoing_fw = fw;
		outgoing_file = hFile;
	}

	return status;

}

// Returns incoming fw pointer
void* GetIncomingFW()
{
	return incoming_fw;
}

// Returns outgoing fw pointer
void* GetOutgoingFW()
{
	return outgoing_fw;
}

// Returns the fw struct size, including all the rules
size_t GetFwSize(char policy)
{
	size_t size = 0;

	if (policy == FWPolicy_Incoming)
	{
		size = (size_t)(sizeof(IncomingFirewall) + (incoming_fw->rules_count * sizeof(FW_Rule)));
	}
	else if (policy == FWPolicy_Outgoing)
	{
		size = (size_t)(sizeof(OutgoingFirewall) + (outgoing_fw->rules_count * sizeof(FW_Rule)));
	}
	else if (policy == 2) // Both
	{
		size = (size_t)(sizeof(IncomingFirewall) + (incoming_fw->rules_count * sizeof(FW_Rule)));
		size += (size_t)(sizeof(OutgoingFirewall) + (outgoing_fw->rules_count * sizeof(FW_Rule)));
	}

	return size;
}



// Update firewall policies, creating a new fw struct for each update to note change the policy while being used
NTSTATUS UpdateFWRules(char* data)
{
	
	NTSTATUS status = STATUS_NOT_FOUND;

	FW_Policy_Update_Info* policy_update_data = (FW_Policy_Update_Info*)data;
	Firewall* fw = 0;
	FW_Rule_Update_Info* rule = 0;
	Firewall* old_fw = 0;
	Firewall* new_fw = 0;
	size_t fw_struct_size = 0;
	size_t rules_count = 0;
	SSIZE_T index = -1;
	BOOLEAN exist = FALSE;

	// Going through all the rules
	for (size_t i = 0; i < policy_update_data->rules_count; i++)
	{

		rule = &(policy_update_data->rules_info[i]);
		exist = FALSE;
		status = STATUS_NOT_FOUND;

		// What FW policy we want to work on
		if (rule->policy == FWPolicy_Incoming)
		{
			fw = incoming_fw;
		}
		else if (rule->policy == FWPolicy_Outgoing)
		{
			fw = outgoing_fw;
		}
		else
		{
			continue; // Change Dahof
		}

		// find the index of the specified rule, if exist
		for (size_t j = 0; j < fw->rules_count && exist == FALSE; j++)
		{

			if (fw->rules[j].protocol == rule->rule.protocol
				&& fw->rules[j].dst_port == rule->rule.dst_port
				&& strcmp(fw->rules[j].ip_str, rule->rule.ip_str) == 0
				&& fw->rules[j].action == rule->rule.action)
			{

				index = j;
				exist = TRUE;
			}
		}

		// remove the rule if it exists
		if (rule->action == FWRule_Delete && exist)
		{

			old_fw = fw;
			rules_count = fw->rules_count;

			// Allocates a new struct for the firewal, we try not to change the struct that can be used simuntanisly
			fw_struct_size = sizeof(IncomingFirewall) + ((rules_count - 1) * sizeof(FW_Rule));
			new_fw = ExAllocatePoolWithTag(PagedPool, fw_struct_size, 'WFSZ');

			if (new_fw)
			{

				new_fw->rules_count = rules_count;

				// Copies all the rules up to the rule we want to remove
				for (SSIZE_T j = 0; j < index; j++)
				{
					memcpy(&(new_fw->rules[j]), &(fw->rules[j]), sizeof(FW_Rule));
				}

				// Copies all the rules after the rule we want to remove
				for (size_t j = (size_t)index + 1; j < fw->rules_count; j++)
				{
					memcpy(&(new_fw->rules[j - 1]), &(fw->rules[j]), sizeof(FW_Rule));
				}

				new_fw->rules_count--;

				fw = new_fw;

				if (old_fw)
				{
					ExFreePoolWithTag(old_fw, 'WFSZ');
				}

				status = STATUS_SUCCESS;
			}

		}

		// append to fw rules list if it doesn't exist
		else if (rule->action == FWRule_Append && exist == FALSE)
		{

			old_fw = fw;
			rules_count = fw->rules_count;

			// Allocates a new struct for the firewal, we try not to change the struct that can be used simuntanisly
			fw_struct_size = sizeof(IncomingFirewall) + ((rules_count + 1) * sizeof(FW_Rule));
			new_fw = ExAllocatePoolWithTag(PagedPool, fw_struct_size, 'WFSZ');

			if (new_fw)
			{
				new_fw->rules_count = rules_count;

				// Copies the old rules
				for (int j = 0; j < new_fw->rules_count; j++)
				{
					memcpy(&(new_fw->rules[j]), &(fw->rules[j]), sizeof(FW_Rule));
				}

				// Copies the new rule
				memcpy(&(new_fw->rules[rules_count]), &(rule->rule), sizeof(FW_Rule));

				new_fw->rules_count++;

				fw = new_fw;

				if (old_fw)
				{
					ExFreePoolWithTag(old_fw, 'WFSZ');
				}

				status = STATUS_SUCCESS;
			}
		}

		// modify rule if it exists - in development
		else if (rule->action == FWRule_Modify && exist)
		{

			memcpy(&(fw->rules[index]), &(rule->rule), sizeof(FW_Rule));
			status = STATUS_SUCCESS;
			// TODO
		}

		if (NT_SUCCESS(status))
		{
			if (rule->policy == FWPolicy_Incoming)
			{
				incoming_fw = fw;
			}
			else if (rule->policy == FWPolicy_Outgoing)
			{
				outgoing_fw = fw;
			}
		}

	}

	if (NT_SUCCESS(status))
	{
		status = SaveFWRules(incoming_fw_db_filename, 1);
		status = SaveFWRules(outgoing_fw_db_filename, 2);
	}

	return status;
}

// Filters outgoing packets accourding to the fw rules
NTSTATUS FilterOutgoingPackets(unsigned char* buffer, unsigned int buffer_size)
{
	NTSTATUS status = STATUS_SUCCESS;
	UNREFERENCED_PARAMETER(buffer_size);

	BOOLEAN checked = FALSE;
	unsigned int tcp_header_size = 0;
	unsigned int data_size = 0;
	unsigned char* data = 0;
	char src_ip_str[16] = { 0 };
	char dst_ip_str[16] = { 0 };

	ipv4_header* ipv4 = 0;
	tcp_header* tcp = 0;

	/*if (outgoing_fw != 0)*/
	if (MmIsAddressValid(outgoing_fw))
	{

		ipv4 = (ipv4_header*)(buffer + sizeof(eth_header_t));
		tcp = (tcp_header*)((char*)ipv4 + sizeof(ipv4_header));

		tcp_header_size = (RtlUshortByteSwap(ipv4->len) - sizeof(ipv4_header));


		// tcp header size includes data size within, 
		// so if substruct the the size with the data and the size without the data we will get the data size
		// (tcp->data_offset << 2) is the tcp header size without the data
		data_size = tcp_header_size - (tcp->data_offset << 2);

		// data is at the end of the tcp header 
		data = (unsigned char*)((char*)tcp + (unsigned int)(tcp->data_offset << 2));

		inet_ntop(ipv4->src_addr, src_ip_str, 16);
		inet_ntop(ipv4->dst_addr, dst_ip_str, 16);

		for (size_t i = 0; i < outgoing_fw->rules_count && checked == FALSE; i++)
		{
			
			if (outgoing_fw->rules[i].protocol == ipv4->proto &&
				outgoing_fw->rules[i].dst_port == RtlUshortByteSwap(tcp->dest_port) &&
				strmatch(outgoing_fw->rules[i].ip_str, dst_ip_str))
			{
				DbgPrint("outgoing\n");
				if (outgoing_fw->rules[i].action == FWAction_Drop)
				{
					status = 1; // Drop
					checked = TRUE;
				}
				else if (outgoing_fw->rules[i].action == FWAction_Allow)
				{
					status = STATUS_SUCCESS; // Allow
					checked = TRUE;
				}
				else if (outgoing_fw->rules[i].action == FWAction_Modify)
				{
					// TODO
					checked = TRUE;
				}

			}
		
		}
	}
	else {
		DbgPrint("Invalid address of outgoing fw - 0x%p\n", outgoing_fw);
		DbgBreakPoint();
	}

	return status;
}




// Filters incoming packets accourding to the fw rules
NTSTATUS FilterIncomingPackets(unsigned char* buffer, unsigned int buffer_size)
{

	NTSTATUS status = STATUS_SUCCESS;
	UNREFERENCED_PARAMETER(buffer_size);


	BOOLEAN checked = FALSE;
	unsigned int tcp_header_size = 0;
	unsigned int data_size = 0;
	unsigned char* data = 0;
	char src_ip_str[16] = { 0 };
	char dst_ip_str[16] = { 0 };

	/*if (incoming_fw != 0)*/
	if(MmIsAddressValid(incoming_fw))
	{


		//unsigned short chksum = 0;
		//char* offset = 0;

		ipv4_header* ipv4 = (ipv4_header*)(buffer + sizeof(eth_header_t));
		tcp_header* tcp = (tcp_header*)((char*)ipv4 + sizeof(ipv4_header));


		tcp_header_size = (RtlUshortByteSwap(ipv4->len) - sizeof(ipv4_header));

		// tcp header size includes data size within, 
		// so if substruct the the size with the data and the size without the data we will get the data size
		// (tcp->data_offset << 2) is the tcp header size without the data
		data_size = tcp_header_size - (tcp->data_offset << 2);

		// data is at the end of the tcp header 
		data = (unsigned char*)((char*)tcp + (unsigned int)(tcp->data_offset << 2));

		inet_ntop(ipv4->src_addr, src_ip_str, 16);
		inet_ntop(ipv4->dst_addr, dst_ip_str, 16);
		
		for (size_t i = 0; i < incoming_fw->rules_count && checked == FALSE; i++)
		{

			if (incoming_fw->rules[i].protocol == ipv4->proto &&
				incoming_fw->rules[i].dst_port == RtlUshortByteSwap(tcp->dest_port) &&
				strmatch(incoming_fw->rules[i].ip_str, src_ip_str))
			{
				DbgPrint("incoming\n");
				if (incoming_fw->rules[i].action == FWAction_Drop)
				{
					status = 1; // Drop
					checked = TRUE;
				}
				else if (incoming_fw->rules[i].action == FWAction_Allow)
				{
					status = STATUS_SUCCESS; // Allow
					checked = TRUE;
				}
				else if (incoming_fw->rules[i].action == FWAction_Modify)
				{
					// TODO
					checked = TRUE;
				}
			}

			
		}
		//DbgBreakPoint();
		/*
		if (ipv4->proto == IPPROTO_TCP)
		{
			tcp_header_size = (RtlUshortByteSwap(ipv4->len) - sizeof(ipv4_header));

			// tcp header size includes data size within,
			// so if substruct the the size with the data and the size without the data we will get the data size
			// (tcp->data_offset << 2) is the tcp header size without the data
			data_size = tcp_header_size - (tcp->data_offset << 2);

			if (data_size)
			{
				inet_ntop(ipv4->src_addr, src_ip_str, 16);
				inet_ntop(ipv4->dst_addr, dst_ip_str, 16);

				// data is at the end of the tcp header
				data = (unsigned char*)((char*)tcp + (tcp->data_offset << 2));

				//if (strcmp(src_ip_str, "188.184.64.53") == 0)
				if(strmatch(src_ip_str, "188.184.64.53"))
				//if (match("*", src_ip_str))
				{

					offset = memmem((const char*)data, data_size, "first", 5);
					while (offset)
					{
						memcpy_s(offset, 5, "Noice", 5);
						chksum = my_checksum((unsigned short*)tcp, tcp_header_size, ipv4->src_addr, ipv4->dst_addr, tcp->checksum);
						tcp->checksum = chksum;

						offset = memmem((const char*)offset, data_size - (offset - (char*)data), "first", 5);
					}

					status = 1;
				}
			}
		}*/
	}

	else {
		DbgPrint("Invalid address of incoming fw - 0x%p\n", incoming_fw);
		DbgBreakPoint();
	}


	return status;
}
