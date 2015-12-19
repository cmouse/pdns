#include "ipv4_network.hpp"

#include <sstream>

std::string to_string(ipv4_network value)
{
	uint32_t native_address = value.native_address();
	std::stringstream out;
	out
		<< (uint32_t{0xffu} & (native_address >> 24))
		<< '.'
		<< (uint32_t{0xffu} & (native_address >> 16))
		<< '.'
		<< (uint32_t{0xffu} & (native_address >> 8))
		<< '.'
		<< (uint32_t{0xffu} & native_address)
		<< '/'
		<< uint32_t{value.network()};
	return out.str();
}

bool operator==(ipv4_network_bitstring const& a, ipv4_network_bitstring const& b) {
	return a.value.network() == b.value.network() && a.value.address() == b.value.address();
}

bool operator!=(ipv4_network_bitstring const& a, ipv4_network_bitstring const& b) {
	return !(a == b);
}

bool is_lexicographic_less(ipv4_network_bitstring const& a, ipv4_network_bitstring const& b) {
	if (a.value.native_address() == b.value.native_address()) {
		// one is prefix of the other; shorter comes first
		return a.value.network() < b.value.network();
	}
	// only the smaller one can be a "real" prefix of the other
	return a.value.native_address() < b.value.native_address();
}

bool is_tree_less(ipv4_network_bitstring const& a, ipv4_network_bitstring const& b) {
	unsigned char trunc_len = std::min(a.value.network(), b.value.network());
	uint32_t const truncate_mask = ipv4_network::netmask(trunc_len);
	uint32_t const a_native_address_trunc = htonl(truncate_mask & a.value.address());
	uint32_t const b_native_address_trunc = htonl(truncate_mask & b.value.address());
	if (a_native_address_trunc < b_native_address_trunc) return true;
	if (a_native_address_trunc == b_native_address_trunc) {
		// one is prefix of the other
		if (a.value.network() == b.value.network()) return false; // a == b
		// 1 <= trunc_len+1 <= 32
		uint32_t const native_next_bit_mask = uint32_t{1} << (32 - (trunc_len+1));
		if (a.value.network() < b.value.network()) { // a prefix of b
			return (native_next_bit_mask & b.value.native_address()) > 0;
		} else { // b prefix of a
			return (native_next_bit_mask & a.value.native_address()) > 0;
		}
	}
	return false;
}

bool is_prefix(ipv4_network_bitstring const& prefix, ipv4_network_bitstring const& str) {
	return prefix == str.truncate(prefix.length());
}

#if !defined(__has_builtin)
# define __has_builtin(x) 0
#endif

ipv4_network_bitstring longest_common_prefix(ipv4_network_bitstring const& a, ipv4_network_bitstring const& b) {
	uint32_t native_uncommon_bits = ntohl((a.value.address() ^ b.value.address()) | ipv4_network::hostmask(std::min(a.value.network(), b.value.network())));
#if defined(__GNUC__) || (__has_builtin(__builtin_clz) && __has_builtin(__builtin_clzl))
	size_t length;
	if (sizeof(unsigned int) >= sizeof(uint32_t)) {
		length = static_cast<size_t>(__builtin_clz(native_uncommon_bits)) - 8*(sizeof(unsigned int) - sizeof(uint32_t));
	} else {
		static_assert(sizeof(unsigned long) >= sizeof(uint32_t), "sizeof(unsigned long) violates standard requirements");
		length = static_cast<size_t>(__builtin_clzl(native_uncommon_bits)) - 8*(sizeof(unsigned long) - sizeof(uint32_t));
	}
#else
	uint32_t native_common_bits = ~native_uncommon_bits;
	size_t length = 0;
	for (uint32_t native_bit = uint32_t{1} << 31; 0 != (native_bit & native_common_bits); native_bit >>= 1, ++length) ;
#endif
	return a.truncate(length);
}
