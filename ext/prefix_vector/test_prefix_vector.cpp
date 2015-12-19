#include "prefix_vector.hpp"
#include "bigendian_bitstring.hpp"
#include "ipv4_network.hpp"

#include <iostream>

#include <netinet/ip.h>
#include <netinet/ip6.h>

void run_ipv4_network() {
	prefix_vector<ipv4_network, uint32_t, ipv4_network_bitstring_traits> routing_table;
	ipv4_network any{0, 0};
	ipv4_network loopback_net{ htonl(INADDR_LOOPBACK), 8 };
	ipv4_network loopback{ htonl(INADDR_LOOPBACK), 32 };
	ipv4_network null{0, 32};

	routing_table.insert_or_assign(any, 20);
	routing_table.insert_or_assign(loopback_net, 10);

	std::cout << routing_table.find(any)->value() << "\n";
	std::cout << routing_table.find(loopback_net)->value() << "\n";
	std::cout << routing_table.find(loopback)->value() << "\n";
	std::cout << routing_table.find(null)->value() << "\n";

	for (auto const& elem: routing_table.subkeys(loopback_net)) {
		std::cout << "subkey: " << to_string(elem.key()) << ": " << elem.value() << "\n";
	}

	decltype(routing_table) const& const_routing_table{routing_table};

	std::cout << const_routing_table.find(any)->value() << "\n";
	std::cout << const_routing_table.find(loopback_net)->value() << "\n";
	std::cout << const_routing_table.find(loopback)->value() << "\n";
	std::cout << const_routing_table.find(null)->value() << "\n";

	for (auto const& elem: const_routing_table.subkeys(loopback_net)) {
		std::cout << "subkey: " << to_string(elem.key()) << ": " << elem.value() << "\n";
	}

	using std::swap;
	decltype(routing_table) other_routing_table;
	swap(routing_table, other_routing_table);
}



struct my_ipv4_network {
	uint32_t addr;
	uint8_t prefix;
};

struct my_ipv4_network_bitstring_traits {
	typedef bigendian::bitstring bitstring;
	typedef my_ipv4_network value_type;

	bitstring value_to_bitstring(value_type value) {
		return bigendian::bitstring(&value.addr, size_t{value.prefix});
	}

	value_type bitstring_to_value(bitstring bs) {
		bs = bs.truncate(32);
		my_ipv4_network result{0, static_cast<unsigned char>(bs.length())};
		bs.set_bitstring(&result.addr, sizeof(result.addr));
		return result;
	}
};

template class prefix_vector<my_ipv4_network, uint32_t, my_ipv4_network_bitstring_traits>;

void run_my_ipv4_network() {
	prefix_vector<my_ipv4_network, uint32_t, my_ipv4_network_bitstring_traits> routing_table;
	my_ipv4_network any{0, 0};
	my_ipv4_network loopback_net{ htonl(INADDR_LOOPBACK), 8 };
	my_ipv4_network loopback{ htonl(INADDR_LOOPBACK), 32 };
	my_ipv4_network null{0, 32};

	routing_table.insert_or_assign(any, 20);
	routing_table.insert_or_assign(loopback_net, 10);

	std::cout << routing_table.find(any)->value() << "\n";
	std::cout << routing_table.find(loopback_net)->value() << "\n";
	std::cout << routing_table.find(loopback)->value() << "\n";
	std::cout << routing_table.find(null)->value() << "\n";

	for (auto const& elem: routing_table.subkeys(loopback_net)) {
		std::cout << "subkey: " << elem.value() << "\n";
	}

	decltype(routing_table) const& const_routing_table{routing_table};

	std::cout << const_routing_table.find(any)->value() << "\n";
	std::cout << const_routing_table.find(loopback_net)->value() << "\n";
	std::cout << const_routing_table.find(loopback)->value() << "\n";
	std::cout << const_routing_table.find(null)->value() << "\n";

	for (auto const& elem: const_routing_table.subkeys(loopback_net)) {
		std::cout << "subkey: " << elem.value() << "\n";
	}

	using std::swap;
	decltype(routing_table) other_routing_table;
	swap(routing_table, other_routing_table);
}

int main() {
	run_ipv4_network();
	run_my_ipv4_network();
	return 0;
}
