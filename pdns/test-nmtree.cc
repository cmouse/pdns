#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_NO_MAIN
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <boost/test/unit_test.hpp>
#include <bitset>
#include "iputils.hh"

using namespace boost;

BOOST_AUTO_TEST_SUITE(nmtree)

BOOST_AUTO_TEST_CASE(test_ComboAddress) {
  NetmaskTree<int> nmt;
  nmt.insert(Netmask("130.161.252.0/24"))->second=0;  
  nmt.insert(Netmask("130.161.0.0/16"))->second=1;
  nmt.insert(Netmask("130.0.0.0/8"))->second=2;

//  BOOST_CHECK(nmt.lookup(ComboAddress("213.244.168.210"))==nullptr);
  auto found=nmt.lookup(ComboAddress("130.161.252.29"));
  BOOST_CHECK(found);
  BOOST_CHECK_EQUAL(found->second, 0);
  found=nmt.lookup(ComboAddress("130.161.180.1"));
  BOOST_CHECK(found);
  BOOST_CHECK_EQUAL(found->second, 1);
  
  found=nmt.lookup(ComboAddress("130.145.180.1"));
  BOOST_CHECK(found);
  BOOST_CHECK_EQUAL(found->second, 2);  
}


BOOST_AUTO_TEST_SUITE_END()
