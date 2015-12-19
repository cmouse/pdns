#pragma once

#include <algorithm>

#include <cassert>

#include <stddef.h>
#include <stdint.h>

// prefix_vector uses an abstract form of "bitstring"s. here is a bigendian bitstring implementation;
// the first bit in the string is the highest bit (0x80) in the first byte
// this directly matches network representation of IP addresses
namespace bigendian {
	class bitstring {
	private:
		void const* m_data{nullptr};
		size_t m_length{0};

	public:
		/* bitstring "concept" interface (also see free methods below) */
		size_t length() const { return m_length; }

		bitstring truncate(size_t length) const {
			return bitstring(m_data, std::min(length, m_length));
		}

		bool operator[](size_t bit_ndx) const;

		/* bigendian::bitstring methods, not part of the "bitstring" concept */
		explicit constexpr bitstring() noexcept = default;
		explicit constexpr bitstring(void const* data, size_t length) noexcept
		: m_data(data), m_length(length) {
		}

		static unsigned char content_mask(size_t length);

		void set_bitstring(void* data, size_t data_size) const;

		unsigned char const* byte_data() const;

		unsigned char get_byte(size_t byte_ndx) const;

		/* get bit at given index in its original position in the byte, i.e. returns 0 or (0x100u >> (ndx % 8)) */
		unsigned char get_bit(size_t bit_ndx) const;

		// return bits of last (incomplete) byte (masks out unused bits);
		// return 0 if there is no incomplete byte.
		unsigned char fraction_byte() const;
	};

	/* bitstring "concept": */

	bool operator==(bitstring const& a, bitstring const& b);
	bool operator!=(bitstring const& a, bitstring const& b);

	// prefix is smaller than string
	bool is_lexicographic_less(bitstring const& a, bitstring const& b);

	// prefix is between those continuing with 0 and those continuing with 1
	bool is_tree_less(bitstring const& a, bitstring const& b);

	bool is_prefix(bitstring const& prefix, bitstring const& str);

	// uses data pointer from a for result
	bitstring longest_common_prefix(bitstring const& a, bitstring const& b);

	/* end of bitstring "concept" */
}

