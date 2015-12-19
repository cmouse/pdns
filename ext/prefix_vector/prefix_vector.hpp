#pragma once

#include "iterator_range.hpp"

#include <algorithm>
#include <functional>
#include <vector>

#include <cassert>

template<typename Key, typename Value, typename KeyBitStringTraits>
class prefix_vector {
public:
	typedef Key key_t;
	typedef Value value_t;

private:
	static constexpr size_t NO_ANCESTOR{~size_t{0}};

	struct inner_element_t {
		// index of longest key which is a "real" prefix of m_key
		size_t m_ancestor{NO_ANCESTOR};
		Key m_key{};
		Value m_value{};

		explicit inner_element_t() = default;

		template<typename ArgKey, typename ArgValue>
		explicit inner_element_t(ArgKey&& key, ArgValue&& value, size_t ancestor)
		: m_ancestor(ancestor), m_key(std::forward<ArgKey>(key)), m_value(std::forward<ArgValue>(value)) {
		}
	};

	typedef std::vector<inner_element_t> container_t;
	typedef typename container_t::iterator inner_iterator;
	typedef typename container_t::const_iterator const_inner_iterator;
	typedef typename KeyBitStringTraits::bitstring bitstring;
	container_t m_container;

public:
	// public visible "entry" type
	class iterator;
	class const_iterator;

	class element_type {
	private:
		inner_iterator m_elem;
		friend class iterator;
		friend class const_iterator;
		friend class prefix_vector;

	public:
		explicit element_type() = default;
		explicit element_type(inner_iterator const& elem)
		: m_elem(elem) {
		}

		const key_t& key() const {
			return m_elem->m_key;
		}

		value_t& value() const {
			return m_elem->m_value;
		}

		friend bool operator==(element_type a, element_type b) { return a.m_elem == b.m_elem; }
		friend bool operator!=(element_type a, element_type b) { return a.m_elem != b.m_elem; }
	};

	class iterator : public std::iterator<std::bidirectional_iterator_tag, element_type> {
	private:
		mutable element_type m_inner;

	public:
		explicit iterator() = default;
		explicit iterator(inner_iterator const& elem)
		: m_inner(elem) {
		}

		element_type& operator*() const { return m_inner; }
		element_type* operator->() const { return &m_inner; }

		iterator& operator++() { ++m_inner.m_elem; return *this; }
		iterator operator++(int) { iterator result{m_inner.m_elem}; ++m_inner.m_elem; return result; }
		iterator& operator--() { --m_inner.m_elem; return *this; }
		iterator operator--(int) { iterator result{m_inner.m_elem}; --m_inner.m_elem; return result; }

		friend bool operator==(iterator a, iterator b) { return a.m_inner == b.m_inner; }
		friend bool operator!=(iterator a, iterator b) { return a.m_inner != b.m_inner; }
	};

	class const_element_type {
	private:
		const_inner_iterator m_elem;
		friend class const_iterator;
		friend class prefix_vector;

	public:
		explicit const_element_type() = default;
		explicit const_element_type(const_inner_iterator const& elem)
		: m_elem(elem) {
		}

		const key_t& key() const {
			return m_elem->m_key;
		}

		const value_t& value() const {
			return m_elem->m_value;
		}

		friend bool operator==(const_element_type a, const_element_type b) { return a.m_elem == b.m_elem; }
		friend bool operator!=(const_element_type a, const_element_type b) { return a.m_elem != b.m_elem; }
	};

	class const_iterator : public std::iterator<std::bidirectional_iterator_tag, const_element_type> {
	private:
		mutable const_element_type m_inner;

	public:
		explicit const_iterator() = default;
		/* explicit */ const_iterator(iterator const& other)
		: m_inner(const_inner_iterator(other->m_elem)) {
		}
		explicit const_iterator(const_inner_iterator const& elem)
		: m_inner(elem) {
		}

		const_element_type& operator*() const { return m_inner; }
		const_element_type* operator->() const { return &m_inner; }

		const_iterator& operator++() { ++m_inner.m_elem; return *this; }
		const_iterator operator++(int) { const_iterator result{m_inner.m_elem}; ++m_inner.m_elem; return result; }
		const_iterator& operator--() { --m_inner.m_elem; return *this; }
		const_iterator operator--(int) { const_iterator result{m_inner.m_elem}; --m_inner.m_elem; return result; }

		friend bool operator==(const_iterator a, const_iterator b) { return a.m_inner == b.m_inner; }
		friend bool operator!=(const_iterator a, const_iterator b) { return a.m_inner != b.m_inner; }
	};

private:
	static bitstring getBitString(key_t const& key) {
		KeyBitStringTraits keyBitStringTraits{};
		return keyBitStringTraits.value_to_bitstring(key);
	}

	struct compare_keys {
		bool operator()(inner_element_t const& a, bitstring const& b) {
			bitstring const a_bitstring = getBitString(a.m_key);
			return is_lexicographic_less(a_bitstring, b);
		}

		bool operator()(bitstring const& a, inner_element_t const& b) {
			bitstring const b_bitstring = getBitString(b.m_key);
			return is_lexicographic_less(a, b_bitstring);
		}
	};

	struct compare_key_prefix {
		size_t prefixLength;

		explicit compare_key_prefix(key_t const& prefix)
		: prefixLength(getBitString(prefix).length()) {
		}

		bool operator()(inner_element_t const& a, bitstring const& b) {
			bitstring const a_bitstring = getBitString(a.m_key).truncate(prefixLength);
			return is_lexicographic_less(a_bitstring, b.truncate(prefixLength));
		}

		bool operator()(bitstring const& a, inner_element_t const& b) {
			bitstring const b_bitstring = getBitString(b.m_key).truncate(prefixLength);
			return is_lexicographic_less(a.truncate(prefixLength), b_bitstring);
		}
	};

	// create "mutable" iterator from const iterator
	inner_iterator mut_it(const_inner_iterator it) {
		return m_container.begin() + (it - m_container.begin());
	}

	// find closest ancestor (-> ancestor with longest key) of key, starting with insert position "pos"
	size_t find_ancestor_index(const_inner_iterator pos, key_t const& key) const {
		if (m_container.empty()) return NO_ANCESTOR;

		bitstring const k = getBitString(key);

		size_t current = static_cast<size_t>(pos - m_container.begin());

		// the insert position could actually be an exact match:
		if (pos != m_container.end() && getBitString(pos->m_key) == k) return current; // exact match

		// all ancestors of an entry at index [x] are either the element at [x-1] or ancestors of [x-1] as well
		// to search for all ancestors of an element that would be inserted at [pos], we just traverse
		// through all ancestors of [pos-1] ([pos-1] could be the ancestor we are looking for too)
		// if there is no [pos-1] then there is no ancestor
		if (pos == m_container.begin()) return NO_ANCESTOR;
		--current;

		for (;;) {
			// invariant: m_container.begin() <= pos < m_container.end()
			if (is_prefix(getBitString(m_container[current].m_key), k)) return current; // prefix match
			if (NO_ANCESTOR == m_container[current].m_ancestor) return NO_ANCESTOR;
			assert(m_container[current].m_ancestor < current);
			current = m_container[current].m_ancestor;
		}
	}

	const_inner_iterator find_ancestor(const_inner_iterator pos, key_t const& key) const {
		size_t ndx = find_ancestor_index(pos, key);
		if (NO_ANCESTOR == ndx) return m_container.end();
		return m_container.begin() + ndx;
	}

	// find node with longest common prefix for key
	const_inner_iterator lookup(key_t const& key) const {
		const_inner_iterator insert_pos = std::lower_bound(m_container.begin(), m_container.end(), getBitString(key), compare_keys{});
		return find_ancestor(insert_pos, key);
	}

	const_inner_iterator lookup_exact(key_t const& key) const {
		bitstring const k = getBitString(key);
		const_inner_iterator insert_pos = std::lower_bound(m_container.begin(), m_container.end(), k, compare_keys{});
		if (m_container.end() == insert_pos || k != getBitString(insert_pos->m_key)) return m_container.end();
		return insert_pos;
	}

	iterator_range<const_inner_iterator> subtree_range(key_t const& key) const {
		bitstring const k = getBitString(key);
		compare_key_prefix cmp{key};
		const_inner_iterator from = std::lower_bound(m_container.begin(), m_container.end(), k, cmp);
		const_inner_iterator to = std::upper_bound(m_container.begin(), m_container.end(), k, cmp);
		return make_iterator_range(from, to);
	}

	std::pair<iterator, bool>  intern_insert(key_t& key, value_t& value, bool overwrite) {
		bitstring const k = getBitString(key);

		inner_iterator pos = std::lower_bound(m_container.begin(), m_container.end(), k, compare_keys{});
		if (m_container.end() != pos && k == getBitString(pos->m_key)) {
			if (!overwrite) return std::pair<iterator, bool>(iterator(pos), false);
			pos->m_value = std::move(value);
			return std::pair<iterator, bool>(iterator(pos), true);
		}

		size_t new_index = static_cast<size_t>(pos - m_container.begin());
		// next "valid" ancestor of new element
		auto ancestor_index = find_ancestor_index(pos, key);
		// we insert a new element at [new_index]. all indices >= new_index need to be incremented:
		assert(NO_ANCESTOR == ancestor_index || ancestor_index < new_index);
		// first come all the nodes which are possible in the subtree of the new element
		// if they end there won't be any more
		// only in this subtree do we replace the old ancestor with the new index
		bool possibly_in_new_subtree = true;
		for (auto& elem: make_iterator_range(pos, m_container.end())) {
			if (elem.m_ancestor == ancestor_index) {
				if (possibly_in_new_subtree) {
					possibly_in_new_subtree = is_prefix(k, getBitString(elem.m_key));
					if (possibly_in_new_subtree) elem.m_ancestor = new_index;
				}
			} else if (NO_ANCESTOR != elem.m_ancestor && elem.m_ancestor >= new_index) {
				++elem.m_ancestor;
			}
		}

		pos = m_container.insert(pos, inner_element_t{std::move(key), std::move(value), ancestor_index});

		return std::pair<iterator, bool>(iterator(pos), true);
	}

	// erase element at given position; return iterator for the (previously) following entry
	inner_iterator intern_erase(inner_iterator pos) {
		size_t old_index = static_cast<size_t>(pos - m_container.begin());
		size_t ancestor_index = pos->m_ancestor;
		bitstring const k = getBitString(pos->m_key);

		// we will remove a new element at [old_index]. all indices >= old_index need to be decremented:
		assert(NO_ANCESTOR == ancestor_index || ancestor_index < old_index);
		// first come all the nodes which are possible in the subtree of the old element
		// if they end there won't be any more
		// only in this subtree do we replace the old index with the ancestor
		bool possibly_in_old_subtree = true;
		for (auto& elem: make_iterator_range(pos, m_container.end())) {
			if (elem.m_ancestor == old_index) {
				if (possibly_in_old_subtree) {
					possibly_in_old_subtree = is_prefix(k, getBitString(elem.m_key));
					if (possibly_in_old_subtree) elem.m_ancestor = ancestor_index;
				}
			} else if (NO_ANCESTOR != elem.m_ancestor && elem.m_ancestor >= old_index) {
				--elem.m_ancestor;
			}
		}

		pos = m_container.erase(pos);

		return pos;
	}

public:
	// find entry with longest matching prefix of key (or end())
	const_iterator find(key_t const& key) const {
		return const_iterator(lookup(key));
	}

	iterator find(key_t const& key) {
		return iterator(mut_it(lookup(key)));
	}

	// find entry with key equal to given key (compares with bitstring)
	const_iterator find_exact(key_t const& key) const {
		return const_iterator(lookup_exact(key));
	}

	iterator find_exact(key_t const& key) {
		return iterator(mut_it(lookup_exact(key)));
	}

	// value from entry found with find() or nullptr
	value_t const* value(key_t const& key) const {
		auto pos = lookup(key);
		return pos == m_container.end() ? nullptr : &pos ->m_value;
	}

	value_t* value(key_t const& key) {
		auto pos = lookup(key);
		return pos == m_container.end() ? nullptr : &mut_it(pos) ->m_value;
	}

	// range with all elements prefixed by given prefix
	iterator_range<const_iterator> subkeys(key_t const& prefix) const {
		auto r = subtree_range(prefix);
		return make_iterator_range(const_iterator(r.begin()), const_iterator(r.end()));
	}
	iterator_range<iterator> subkeys(key_t const& prefix) {
		auto r = subtree_range(prefix);
		return make_iterator_range(iterator(mut_it(r.begin())), iterator(mut_it(r.end())));
	}

	// insert, but don't overwrite existing entry (returns false if key is already present)
	std::pair<iterator, bool> insert(key_t key, value_t value) {
		return intern_insert(key, value, false);
	}

	// insert, or assign if key is already present (returns false if key is already present)
	std::pair<iterator, bool> insert_or_assign(key_t key, value_t value) {
		return intern_insert(key, value, true);
	}

	// erase element at given position; return iterator for the (previously) following entry
	iterator erase(const_iterator it) {
		return iterator(intern_erase(mut_it(it->m_elem)));

	}

	// erase element with given key. returns how many elements were deleted (0 or 1)
	size_t erase(key_t const& key) {
		const_inner_iterator pos = lookup_exact(key);
		if (pos == m_container.end()) return 0;
		intern_erase(mut_it(pos));
		return 1;
	}

	// standard routines

	friend void swap(prefix_vector& a, prefix_vector& b) {
		using std::swap;
		swap(a.m_container, b.m_container);
	}

	iterator begin() { return iterator(m_container.begin()); }
	iterator end() { return iterator(m_container.end()); }
	const_iterator begin() const { return const_iterator(m_container.begin()); }
	const_iterator end() const { return const_iterator(m_container.end()); }
	const_iterator cbegin() const { return const_iterator(m_container.begin()); }
	const_iterator cend() const { return const_iterator(m_container.end()); }
};
