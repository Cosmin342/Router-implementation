#include <queue.h>
#include "skel.h"
#define MAC_SIZE		6
#define MAX_LINE		60
#define MAX_RTABLE_SIZE	100000

//Structuri pentru tabela de rutare si pentru tabela arp
struct route_table {
	uint32_t prefix;
	uint32_t next_hop;
	uint32_t mask;
	int interface;
};

struct arp_table {
	uint32_t ip;
	uint8_t mac[MAC_SIZE];
};

//Functie pentru parsarea tabelei de rutare
struct route_table* read_rtable(int* entry_number, char* filename){
	struct route_table* rtable = calloc(MAX_RTABLE_SIZE,
		sizeof(struct route_table));
	//In line va fi retinuta o linie
	char line[MAX_LINE];
	FILE* input = fopen(filename, "r");
	if (input == NULL){
		free(rtable);
		exit(-1);
	}
	while (fgets(line, MAX_LINE, input)){
		int i = 0;
		char *token = strtok(line, " ");
		/*
		Pentru fiecare linie fac strtok si extrag in functie de i datele unei
		linii din tabela
		*/
		while (token != NULL){
			char interface[5];
			switch (i){
				case 0:
					rtable[*entry_number].prefix = inet_addr(token);
					break;
				case 1:
					rtable[*entry_number].next_hop = inet_addr(token);
					break;
				case 2:
					rtable[*entry_number].mask = inet_addr(token);
					break;
				default:
					strcpy(interface, token);
					interface[strlen(interface) - 1] = '\0';
					rtable[*entry_number].interface	= atoi(interface);
					break;
			}
			i++;
			token = strtok(NULL, " ");
		}
		//entry_number va reprezenta la final numarul de linii din tabela
		(*entry_number)++;
	}
	fclose(input);
	return rtable;
}

//Functie pentru cautarea in tabela de rutare
struct route_table *get_route(uint32_t dest_ip,	struct route_table* rtable,
	int left, int right) {
	//route ramane NULL daca esueaza cautarea
	struct route_table* route = NULL;
	/*
	Daca indicele din stanga ajunge mai mare decat cel din drepta, nu exista
	o ruta pentru ip-ul dat ca parametru
	*/
	while (left <= right) {
		int mid = (left + right) / 2;
		//Daca intrarea din mijloc este cea mai specifica, cautarea se opreste
		if ((dest_ip & rtable[mid].mask) == rtable[mid].prefix) {
			route = &rtable[mid];
			break;
		}
		/*
		Altfel, daca ip-ul cu masca din mijloc este mai mare decat prefixul se
		va cauta in partea stanga. In caz contrar, se verifica in dreapta
		*/
		if ((dest_ip & rtable[mid].mask) > rtable[mid].prefix) {
			right = mid - 1;
		}
		else {
			left = mid + 1;
		}
	}
	return route;
}

/*
Functie pentru intoarcerea intrarii arp pentru un ip, daca exista in tabela
arp
*/
struct arp_table* get_arp_entry(uint32_t ip, struct arp_table* arp_table,
	int arp_length) {
	int i;
	for (i = 0; i < arp_length; i++) {
		//Daca ip-ul exista in tabela, se intoarce intrarea respectiva
		if (arp_table[i].ip == ip){
			return &arp_table[i];
		}
	}
	//Altfel se intoarce null
	return NULL;
}

//Functie utilizata pentru sortarea descrescatoare a tabelei de rutare
int compara(const void *a, const void *b) {
	return (*(struct route_table*)b).prefix - (*(struct route_table*)a).prefix;
}

//Functie pentru trimiterea unui arp reply
void send_arp_reply(packet m, struct arp_header* arp_hdr) {
	//Se creeaza un nou ether_header
	struct ether_header *eth_hdr = calloc(1, sizeof(struct ether_header));
	uint8_t* searched_mac = malloc(arp_hdr->hlen * sizeof(uint8_t));
	/*
	Se extrage adresa mac a router-ului de pe interfata de pe care a venit
	arp request-ul
	*/
	get_interface_mac(m.interface, searched_mac);
	/*
	Se modifica eth_hdr setand campurile acestuia cu adresa mac a router-ului,
	adresa host-ului/router-ului de unde a venit pachetul si tipul header-ului
	*/
	build_ethhdr(eth_hdr, searched_mac, arp_hdr->sha, htons(ETHERTYPE_ARP));
	//Se trimite utilizand functia send_arp cu parametrii aferenti
	send_arp(inet_addr(get_interface_ip(m.interface)), arp_hdr->tpa, eth_hdr,
		m.interface, htons(ARPOP_REPLY));
}

/*
Functie pentru trimiterea pachetelor dintr-o coada cand se primeste un arp
reply si pentru actualizarea tabelei arp
*/
void send_and_update(struct arp_header* arp_hdr, struct arp_table* arp_table,
	queue q, packet m, int* arp_length, struct route_table* rtable,
	int entry_number) {
	//Se introduce o noua intrare in tabela arp
	arp_table[*arp_length].ip = arp_hdr->spa;
	memcpy(arp_table[*arp_length].mac, arp_hdr->sha,
		arp_hdr->hlen * sizeof(uint8_t));
	(*arp_length)++;
	/*
	Se creeaza o coada auxiliara pentru pachetele care nu trebuie inca trimise
	*/
	queue aux = queue_create();
	while (queue_empty(q) == 0) {
		//Se extrage cate un pachet din coada + ip header-ul sau
		packet* pack = queue_deq(q);
		struct iphdr *ip_hdr = (struct iphdr*) ((*pack).payload +
			sizeof(struct ether_header));
		//Se cauta cea mai specifica intrare in tabela de rutare
		struct route_table *route = get_route(ip_hdr->daddr, rtable, 0,
			entry_number - 1);
		/*
		Daca next hop-ul e diferit de adresa ip de unde a venit reply-ul,
		pachetul va fi pus in coada auxiliara
		*/
		if (route->next_hop != arp_hdr->spa) {
			queue_enq(aux, &pack);
			continue;
		}
		//Altfel, se completeaza eth_hdr cu adresele mac corespunzatoare
		struct ether_header *eth_hdr = (struct ether_header*) m.payload;
		build_ethhdr(eth_hdr, arp_hdr->tha, arp_hdr->sha, htons(ETHERTYPE_IP));
		send_packet(m.interface, pack);
	}
	//La final, continutul din aux este adaugat in q
	while (queue_empty(aux) == 0) {
		queue_enq(q, queue_deq(aux));
	}
}

/*
Functie pentru trimiterea unui arp_request daca nu se cunoaste adresa mac a
urmatorului hop
*/
void send_arp_request(queue q, struct route_table* route, packet m) {
	packet pack;
	int i;
	//In coada se introduce o copie a pachetului pentru a nu fi corupt ulterior
	memcpy(&pack, &m, sizeof(m));
	queue_enq(q, &pack);
	//Se creaza un nou eth_hdr pentru trimiterea arp-ului
	struct ether_header *eth_hdr = calloc(1, sizeof(struct ether_header));
	uint8_t* my_mac = malloc(MAC_SIZE * sizeof(uint8_t));
	get_interface_mac(route->interface, my_mac);
	/*
	La sender se pune adresa mac a router-ului, iar la destination se va pune
	ff:ff:ff:ff:ff:ff (de 6 ori 0xff) pentru a forta host-ul sa introduca
	adresa sa mac
	*/
	memcpy(eth_hdr->ether_shost, my_mac, MAC_SIZE * sizeof(uint8_t));
	for (i = 0; i < MAC_SIZE; i++){
		eth_hdr->ether_dhost[i] = 0xff;
	}
	eth_hdr->ether_type = htons(ETHERTYPE_ARP);
	send_arp(route->next_hop, inet_addr(get_interface_ip(route->interface)),
		eth_hdr, route->interface, htons(ARPOP_REQUEST));
}

int main(int argc, char *argv[])
{
	packet m;
	int rc, entry_number = 0, arp_length = 0;
	struct arp_table* arp_table = calloc(100, sizeof(struct arp_table));
	queue q = queue_create();

	init(argc - 2, argv + 2);
	/*
	Se parseaza tabela de rutare si se sorteaza pentru a putea face o cautare
	binara
	*/
	struct route_table* rtable = read_rtable(&entry_number, argv[1]);
	qsort(rtable, entry_number, sizeof(struct route_table), compara);
	while (1) {
		rc = get_packet(&m);
		DIE(rc < 0, "get_message");
		//Se verifica daca pachetul este de tip arp
		struct arp_header* arp_hdr = parse_arp(m.payload);
		//In caz afirmativ, se verifica tipul sau
		if (arp_hdr != NULL){
			//Daca pachetul este de tip request, se va trimite un reply
			if (htons(arp_hdr->op) == ARPOP_REQUEST){
				send_arp_reply(m, arp_hdr);
			}
			/*
			Daca este de tip reply, se va actualiza tabela arp si se vor
			dirija pachete din coada, daca exista
			*/
			if (htons(arp_hdr->op) == ARPOP_REPLY){
				send_and_update(arp_hdr, arp_table, q, m, &arp_length, rtable,
					entry_number);
			}
			continue;
		}
		//Se verifica daca pachetul primit este de tip icmp
		struct icmphdr* icmp_hdr = parse_icmp(m.payload);
		if (icmp_hdr != NULL) {
			/*
			In caz afirmativ, se vor extrage ip header-ul si ether header-ul
			si se va verifica daca este un pachet de tip echo
			*/
			struct iphdr *ip_hdr = (struct iphdr*) (m.payload +
				sizeof(struct ether_header));
			struct ether_header *eth_hdr = (struct ether_header*) m.payload;
			if (icmp_hdr->type == ICMP_ECHO) {
				//Daca este adresat router-ului, se va trimite un reply
				if (ip_hdr->daddr == inet_addr(get_interface_ip(m.interface))){
					send_icmp(ip_hdr->saddr, ip_hdr->daddr,
						eth_hdr->ether_dhost, eth_hdr->ether_shost,
						0, icmp_hdr->code, m.interface, icmp_hdr->un.echo.id,
						icmp_hdr->un.echo.sequence);
					continue;
				}
				//Altfel, se verifica daca exista ruta pana la destinatie
				else {
					struct route_table *route = get_route(ip_hdr->daddr,
						rtable, 0, entry_number - 1);
					/*
					Daca nu exista, se va trimite un icmp de tip host
					unreachable
					*/
					if (route == NULL) {
						send_icmp_error(ip_hdr->saddr, ip_hdr->daddr,
							eth_hdr->ether_dhost, eth_hdr->ether_shost, 3, 0,
							m.interface);
						continue;
					}
				}
			}
		}
		/*
		Daca pachetul nu este nici icmp, nici arp, va fi tratat ca un pachet
		obisnuit
		*/
		struct ether_header *eth_hdr = (struct ether_header*) m.payload;
		struct iphdr *ip_hdr = (struct iphdr*) (m.payload +
			sizeof(struct ether_header));
		struct route_table *route = get_route(ip_hdr->daddr, rtable, 0,
			entry_number - 1);
		/*
		Daca nu existaruta , se va trimite un icmp de tip host unreachable
		*/
		if (route == NULL) {
			send_icmp_error(ip_hdr->saddr, ip_hdr->daddr, eth_hdr->ether_dhost,
				eth_hdr->ether_shost, 3, 0, m.interface);
			continue;
		}
		/*
		Daca ttl-ul este mai mic sau egal cu 1 (deoarece fac decrementarea
		ulterior), se va trimite un mesaj icmp de tip time exceeded
		*/
		if (ip_hdr->ttl <= 1){
			send_icmp(ip_hdr->saddr, ip_hdr->daddr, eth_hdr->ether_dhost,
				eth_hdr->ether_shost, ICMP_TIME_EXCEEDED, 0, m.interface, 0, 0);
			continue;
		}
		//Daca checksum-ul este incorect, pachetul este aruncat
		if (ip_checksum(ip_hdr, sizeof(struct iphdr)) != 0){
			continue;
		}
		//Se decrementeaza ttl-ul si se actualizeaza checksum-ul
		(ip_hdr->ttl)--;
		ip_hdr->check = 0;
		ip_hdr->check = ip_checksum(ip_hdr, sizeof(struct iphdr));
		//Se verifica daca adresa mac pentru urmatorul hop este in tabela arp
		struct arp_table *atable_entry = get_arp_entry(route->next_hop,
			arp_table, arp_length);
		/*
		Daca nu exista, se va trimite un arp request si se va pune pachetul in
		coada
		*/
		if (atable_entry == NULL){
			send_arp_request(q, route, m);
			continue;
		}
		//Daca exista, se actualizeaza eth_hdr si se trimite pachetul
		uint8_t* my_mac = malloc(MAC_SIZE * sizeof(uint8_t));
		get_interface_mac(route->interface, my_mac);
		build_ethhdr(eth_hdr, my_mac, atable_entry->mac, htons(ETHERTYPE_IP));
		send_packet(route->interface, &m);
	}
}
