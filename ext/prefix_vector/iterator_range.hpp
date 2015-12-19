#pragma once

// a generic iterator range helper
template<typename Iterator>
class iterator_range {
private:
	Iterator m_begin, m_end;
public:
	typedef Iterator iterator_t;

	iterator_range() = default;
	explicit iterator_range(iterator_t from, iterator_t to)
	: m_begin(from), m_end(to) {
	}

	iterator_t begin() const { return m_begin; }
	iterator_t end() const { return m_end; }
};

template<typename Iterator>
iterator_range<Iterator> make_iterator_range(Iterator const& from, Iterator const& to) {
	return iterator_range<Iterator>(from, to);
}
