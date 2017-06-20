// Include libraries
// We do not want the warnings about the old deprecated and unsecure CRT functions since these examples can be compiled under *nix as well
#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#else
#include <netinet/in.h>
#include <time.h>
#endif

#include "Functions.h"
using namespace std;

void packet_handler_wifi(struct pcap_pkthdr* packet_header, unsigned char* packet_data);
void packet_handler_eth(struct pcap_pkthdr* packet_header, unsigned char* packet_data);
void reconstruct_message();

pcap_t* device_handle_in_wifi, *device_handle_in_eth;
static int packet_num = 0;
unsigned int last_packet_size;
static int packet_num_wifi_write = 0;
static int packet_num_eth_write = 0;
static int packet_num_wifi_read = 0;
static int packet_num_eth_read = 0;
static unsigned int total_size = MAX_LEN;
unsigned char** packet_buffer;
ex_udp_datagram* packet_buffer_eth[MAX_LEN];
unsigned char* packet_wifi;
unsigned char* packet_eth;
unsigned char* message;

FILE* fp;

thread *wifi_cap_thread;
thread *eth_cap_thread;
thread *sniff_thread;

void wifi_thread_handle();
void eth_thread_handle();

condition_variable wifi_cv;
condition_variable eth_cv;

bool eth_wait = false;
bool wifi_wait = false;

mutex packet_num_mutex;
mutex packet_buff_mutex;
mutex stdout_mutex;

unsigned char client_wifi_mac_addr[6] = { 0x90, 0xcd, 0xb6, 0x2c, 0x40, 0x39 };
unsigned char client_eth_mac_addr[6] = { 0x98, 0x40, 0xbb, 0x14, 0x59, 0x91 };
unsigned char server_mac_addr[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

unsigned char client_wifi_ip_addr[4] = { 192, 168, 0, 16 };
unsigned char client_eth_ip_addr[4] = { 169, 254, 176, 102 };

unsigned char server_wifi_ip_addr[4] = { 192, 168, 0, 17 };
unsigned char server_eth_ip_addr[4] = { 169, 254, 176, 100 };

struct pcap_pkthdr* packet_header_wifi;
unsigned char* packet_data_wifi;

struct pcap_pkthdr* packet_header_eth;
unsigned char* packet_data_eth;

unsigned char *ack_packet_wifi;
unsigned char *ack_packet_eth;

ex_udp_datagram *rec_wifi_udp_d;
ex_udp_datagram *rec_eth_udp_d;

const int PACKET_SIZE = 1400;

int main()
{
    int i = 0;
    int device_number[2];
    int sentBytes;
	pcap_if_t* devices;
	pcap_if_t* device[2];
	char error_buffer [PCAP_ERRBUF_SIZE];
	unsigned int netmask;

	char filter_exp2[] = "udp port 27015 and ip dst 169.254.176.102";		//port and eth ip
	char filter_exp[] = "udp port 27015 and ip dst 192.168.0.16";			//port and wifi ip
	struct bpf_program fcode;
	struct bpf_program fcode2;

	//Retrieve the device list on the local machine 
	if (pcap_findalldevs(&devices, error_buffer) == -1)
	{
		printf("Error in pcap_findalldevs: %s\n", error_buffer);
		return -1;
	}

	// Pick two device from the list
	for (int j = 0; j < 2; j++) 
	{
		for (device[j] = devices; device[j]; device[j] = device[j]->next)
		{
			printf("%d. %s", ++i, device[j]->name);
			if (device[j]->description)
				printf(" (%s)\n", device[j]->description);
			else
				printf(" (No description available)\n");
		}

		// Check if list is empty
		if (i == 0)
		{
			printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
			return -1;
		}

		//printf("Enter the output interface \n");
		// Print the list
		/*if (j == 0)
		{
			printf("Enter Wi-Fi interface number (1-%d):", i);
			scanf("%d", &device_number[j]);
		}
		if (j == 1)
		{
			printf("Enter Ethernet interface number (1-%d):", i);
			scanf("%d", &device_number[j]);
		}*/

		printf("Enter Ethernet interface number (1-%d):", i);
		scanf("%d", &device_number[j]);

		if (device_number[j] < 1 || device_number[j] > i)
		{
			printf("\nInterface number out of range.\n");
			return -1;
		}

		// Select the first device...
		device[j] = devices;
		// ...and then jump to chosen devices
		for (i = 0; i < device_number[j] - 1; i++)
		{
			device[j] = device[j]->next;
		}
	}

	// Open the input adapter wifi
	if ((device_handle_in_wifi = pcap_open_live(device[0]->name, 65536, 0, 1000, error_buffer)) == NULL)
	{
		printf("\n Unable to open adapter %s.\n", device[0]->name);
		return -1;
	}
	
	// Open the output adapter eth
	if ((device_handle_in_eth = pcap_open_live(device[1]->name, 65536, 0, 1000, error_buffer)) == NULL)
	{
		printf("\n Unable to open adapter %s.\n", device[1]->name);
		return -1;
	}
	
	// Check the link layer. We support only Ethernet for simplicity.
	if(pcap_datalink(device_handle_in_wifi) != DLT_EN10MB || pcap_datalink(device_handle_in_eth) != DLT_EN10MB)
	{
		printf("\nThis program works only on Ethernet networks.\n");
		return -1;
	}
	
	for (int j = 0; j < 2; j++)
	{
		if (!device[j]->addresses->netmask)
			netmask = 0;
		else
			netmask = ((struct sockaddr_in *)(device[j]->addresses->netmask))->sin_addr.s_addr;
	}
	
	// Compile the filter    
	if (pcap_compile(device_handle_in_wifi, &fcode, filter_exp, 1, netmask) < 0 || pcap_compile(device_handle_in_eth, &fcode2, filter_exp2, 1, netmask) < 0)
	{
		printf("\n Unable to compile the packet filter. Check the syntax.\n");
		return -1;
	}

	// Set the filter
	if (pcap_setfilter(device_handle_in_wifi, &fcode) < 0 || pcap_setfilter(device_handle_in_eth, &fcode2) < 0)
	{
		printf("\n Error setting the filter.\n");
		return -1;
	}

	fp = fopen("output.wav","wb");

	if (fp == NULL)
	{
		printf("Can't open !");
		return -1;
	}
	
	initialize(&packet_header_wifi, &packet_data_wifi);
	initialize(&packet_header_eth, &packet_data_eth);
	
	make_ack_packet(&ack_packet_wifi, packet_data_wifi, packet_header_wifi, PORT_NUMBER);
	make_ack_packet(&ack_packet_eth, packet_data_wifi, packet_header_wifi, PORT_NUMBER);
	
	set_addresses(&ack_packet_wifi, 1, client_wifi_mac_addr, server_mac_addr, client_wifi_ip_addr, server_wifi_ip_addr);
	set_addresses(&ack_packet_eth, 1, client_eth_mac_addr, server_mac_addr, client_eth_ip_addr, server_eth_ip_addr);

	rec_wifi_udp_d = new ex_udp_datagram(ack_packet_wifi);
	rec_eth_udp_d = new ex_udp_datagram(ack_packet_eth);

	rec_eth_udp_d->iph->checksum = 0;
	rec_wifi_udp_d->iph->checksum = 0;

	rec_wifi_udp_d->iph->checksum = ip_checksum(rec_wifi_udp_d->iph, rec_wifi_udp_d->iph->header_length * 4);
	rec_eth_udp_d->iph->checksum = ip_checksum(rec_eth_udp_d->iph, rec_eth_udp_d->iph->header_length * 4);
	
	wifi_cap_thread = new thread(wifi_thread_handle);
	eth_cap_thread = new thread(eth_thread_handle);

	wifi_cap_thread->join();
	eth_cap_thread->join();
	
	reconstruct_message();

	fclose(fp);
	// !!! IMPORTANT: remember to close the output adapter, otherwise there will be no guarantee that all the packets will be sent!
	pcap_close(device_handle_in_wifi);
	pcap_close(device_handle_in_eth);

	return 0;
}

void wifi_thread_handle() 
{
	while(1)
	{
		packet_num_mutex.lock();
		if (packet_num == total_size)
		{
			packet_num_mutex.unlock();
			break;
		}
		packet_num_mutex.unlock();

		if (pcap_next_ex(device_handle_in_wifi, &packet_header_wifi, (const u_char**)&packet_data_wifi) == 1)
		{
			packet_handler_wifi(packet_header_wifi, packet_data_wifi);
		}
	}
}

// Callback function invoked by libpcap/WinPcap for every incoming packet form WiFi
void packet_handler_wifi(struct pcap_pkthdr* packet_header, unsigned char* packet_data)
{
	ex_udp_datagram* recv_packet;
	recv_packet = new ex_udp_datagram(packet_header, packet_data);

	u_long seq_num = (u_long)ntohl(*((u_long*)recv_packet->seq_number));

	stdout_mutex.lock();
	printf("Wi-Fi_Seq: %d\n", seq_num);
	stdout_mutex.unlock();

	if (seq_num == 0)
	{
		//total_size = ntohl(*(rec_packet->data));
		unsigned int* data_size = (unsigned int*)(recv_packet->data);
		//total_size = ntohl(*gepek);
		//printf("Total size :\n",total_size);

		*(rec_wifi_udp_d->seq_number) = *(recv_packet->seq_number);

		packet_buff_mutex.lock();
		if (packet_buffer == NULL)
		{
			total_size = ntohl(*data_size);
			packet_buffer = new unsigned char*[total_size];
			for (int i = 0; i < total_size; i++)
				packet_buffer[i] = NULL;
		}
		packet_buff_mutex.unlock();

		if (pcap_sendpacket(device_handle_in_wifi, ack_packet_wifi, 4 + sizeof(ethernet_header) + 20 + sizeof(udp_header)) == -1)
		{
			//printf("Warning: The packet will not be sent.\n");
		}
	}
	else
	{
		packet_buff_mutex.lock();
		if (packet_buffer[seq_num - 1] == NULL)
		{
			packet_num_mutex.lock();
			packet_num++;
			packet_num_mutex.unlock();
			packet_buffer[seq_num - 1] = new unsigned char[ntohs(recv_packet->uh->datagram_length) - sizeof(udp_header) - 4];
			memcpy(packet_buffer[seq_num - 1], recv_packet->data, ntohs(recv_packet->uh->datagram_length) - sizeof(udp_header)-4);

		}
		packet_buff_mutex.unlock();

		if (seq_num == total_size)
			last_packet_size = ntohs(recv_packet->uh->datagram_length) - sizeof(udp_header) - 4;

		*(rec_wifi_udp_d->seq_number) = htonl(seq_num);

		if (pcap_sendpacket(device_handle_in_wifi, ack_packet_wifi, 4 + sizeof(ethernet_header) + 20 + sizeof(udp_header)) == -1)
		{
			//printf("Warning: The packet will not be sent.\n");
		}
	}
}

void eth_thread_handle()
{
	while (1)
	{
		packet_num_mutex.lock();
		if (packet_num == total_size)
		{
			packet_num_mutex.unlock();
			break;
		}
		packet_num_mutex.unlock();

		if (pcap_next_ex(device_handle_in_eth, &packet_header_eth, (const u_char**)&packet_data_eth) == 1)
		{
			packet_handler_eth(packet_header_eth, packet_data_eth);
		}
	}
}

// Callback function invoked by libpcap/WinPcap for every incoming packet form Eth
void packet_handler_eth(struct pcap_pkthdr* packet_header,unsigned char* packet_data)
{
	ex_udp_datagram* recv_packet;
	recv_packet = new ex_udp_datagram(packet_header, packet_data);

	u_long seq_num = (u_long)ntohl(*((u_long*)recv_packet->seq_number));

	stdout_mutex.lock();
	printf("Eth_Seq: %d\n", seq_num);
	stdout_mutex.unlock();

	if (seq_num == 0)
	{
		//total_size = ntohl(*(rec_packet->data));
		unsigned int* data_size = (unsigned int*)(recv_packet->data);
		
		//printf("Total size :\n", total_size);

		*(rec_eth_udp_d->seq_number) = *(recv_packet->seq_number);

		packet_buff_mutex.lock();
		if (packet_buffer == NULL)
		{
			total_size = ntohl(*data_size);
			packet_buffer = new unsigned char*[total_size];
			for (int i = 0; i < total_size; i++)
				packet_buffer[i] = NULL;
		}
		packet_buff_mutex.unlock();


		if (pcap_sendpacket(device_handle_in_eth, ack_packet_eth, 4 + sizeof(ethernet_header) + 20 + sizeof(udp_header)) == -1)
		{
			//printf("Warning: The packet will not be sent.\n");
		}
	}
	else
	{
		packet_buff_mutex.lock();
		if (packet_buffer[seq_num - 1] == NULL)
		{
			packet_num_mutex.lock();
			packet_num++;
			packet_num_mutex.unlock();
			packet_buffer[seq_num - 1] = new unsigned char[ntohs(recv_packet->uh->datagram_length) - sizeof(udp_header) - 4];
			memcpy(packet_buffer[seq_num - 1], recv_packet->data, ntohs(recv_packet->uh->datagram_length) - sizeof(udp_header) - 4);
		}
		packet_buff_mutex.unlock();

		if (seq_num == total_size)
			last_packet_size = ntohs(recv_packet->uh->datagram_length) - sizeof(udp_header) - 4;

		*(rec_eth_udp_d->seq_number) = htonl(seq_num);

		if (pcap_sendpacket(device_handle_in_eth, ack_packet_eth, 4 + sizeof(ethernet_header) + 20 + sizeof(udp_header)) == -1)
		{
			//printf("Warning: The packet will not be sent.\n");
		}
	}
}

void reconstruct_message() 
{
	for (int i = 0; i < (total_size-1); i++)
		fwrite(packet_buffer[i], sizeof(unsigned char), PACKET_SIZE, fp);
	fwrite(packet_buffer[total_size-1], sizeof(unsigned char), last_packet_size, fp);
	getchar();
}