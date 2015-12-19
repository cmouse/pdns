#pragma once

#include <algorithm>
#include <string>

#include <stddef.h>
#include <stdint.h>
#include <arpa/inet.h>

class ipv4_network {
private:
	// network byte order! always clean, i.e. contains no bits outside the netmask.
	uint32_t m_address{0};
	// network length
	unsigned char m_network{0};

public:
	static uint32_t hostmask(unsigned char network) {
		if (network >= 32) network = 32;
		return htonl(static_cast<uint32_t>((uint64_t{1} << (32u - network)) - 1u));
	}

	static uint32_t netmask(unsigned char network) {
		return ~hostmask(network);
	}

	ipv4_network() = default;
	explicit ipv4_network(uint32_t address, unsigned char network)
	: m_address(address & netmask(network)), m_network(std::min<unsigned char>(network, 32u)) {
	}
	explicit ipv4_network(uint32_t address)
	: m_address(address), m_network(32) {
	}

	uint32_t address() const { return m_address; }
	uint32_t native_address() const { return ntohl(m_address); }
	unsigned char network() const { return m_network; }
};
std::string to_string(ipv4_network value);

struct ipv4_network_bitstring {
	ipv4_network value{};

	ipv4_network_bitstring() = default;
	explicit ipv4_network_bitstring(ipv4_network val)
	: value(val) {
	}

	size_t length() const { return value.network(); }

	ipv4_network_bitstring truncate(size_t length) const {
		unsigned char new_length = static_cast<unsigned char>(std::min<size_t>(length, value.network()));
		return ipv4_network_bitstring(ipv4_network(value.address(), new_length));
	}

	bool operator[](size_t ndx) const {
		uint32_t const native_mask = uint32_t{1} << (31u - (ndx % 32u));
		return 0 != (value.native_address() & native_mask);
	}
};
bool operator==(ipv4_network_bitstring const& a, ipv4_network_bitstring const& b);
bool operator!=(ipv4_network_bitstring const& a, ipv4_network_bitstring const& b);

bool is_lexicographic_less(ipv4_network_bitstring const& a, ipv4_network_bitstring const& b);

bool is_tree_less(ipv4_network_bitstring const& a, ipv4_network_bitstring const& b);

bool is_prefix(ipv4_network_bitstring const& prefix, ipv4_network_bitstring const& str);

ipv4_network_bitstring longest_common_prefix(ipv4_network_bitstring const& a, ipv4_network_bitstring const& b);

struct ipv4_network_bitstring_traits {
	typedef ipv4_network_bitstring bitstring;
	typedef ipv4_network value_type;

	bitstring value_to_bitstring(value_type val) {
		return bitstring(val);
	}

	value_type bitstring_to_value(bitstring bs) {
		return bs.value;
	}
};
