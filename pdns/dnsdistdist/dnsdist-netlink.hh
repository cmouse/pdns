#pragma once

int dnsdist_open_netlink(void);
int dnsdist_should_reopen(int sock, bool &reopen_r);
