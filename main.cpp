#include <cstddef>
#include <time.h>

#include <map>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <iostream>
#include <algorithm>
using namespace std;

#if ! defined(__linux__)
	#include <WinSock2.h>
	#include <windows.h>
	#include <ntddndis.h>
	#include <pcap.h> // after windows includes  
	#include "packet32.h"
#else
	#include <sys/socket.h>
	#include <netpacket/packet.h>
	#include <net/ethernet.h>
	#include <pcap.h>
	#include <unistd.h>
#endif


bool isconf(string &s, const string &pref) {
    if (pref.size() > s.size()) return false;
    if (pref.compare(s.substr(0, pref.size())) != 0) return false;
    s = s.substr(pref.size());
    return true;
}
bool atoi(const string &s, int &x) {
    istringstream iss(s);
    return !!(iss >> x);
}

struct Env {
    typedef map<string, bool (*)()> fnmap;
    pcap_t *fp;
    fnmap fn;
    bool needclose;
    
// configuration
    string sniff, filter;
    int snaplen, bufsize, promisc, timeout, optimize;
// configuration end
    
    Env() {
        fp = NULL;
        needclose = false;
        // default values, override them in conf in
        // key=val
        // syntax
        snaplen = 123;
        bufsize = 20971520; // 20 MiB
        promisc = 0;
        timeout = 250;
        optimize = 1;
        
        ifstream fin("conf.txt");
        if (!fin) {
            cerr << "'conf.txt' absent\n";
            return;
        }
        string line;
        while (getline(fin, line)) {
            if (isconf(line, "sniff=")) {
                sniff = line;
            } else if (isconf(line, "filter=")) {
                filter = line;
            }
            
            #define confnum(varname) \
                else if (isconf(line, #varname "=")) { \
                    if (!atoi(line, varname)) { \
                        cerr << "couldn't parse " #varname " in 'conf.txt': " << line << "\n"; \
                    } \
                }
            
                confnum(snaplen)
                confnum(bufsize)
                confnum(promisc)
                confnum(timeout)
                confnum(optimize)
            #undef confnum
            
            else {
                
            }
        }
    }
} env;

bool p_fdevs() {
    char errbuf[PCAP_ERRBUF_SIZE + 1] = "";
	pcap_if_t *alldevs = NULL;
	if (pcap_findalldevs(&alldevs, errbuf) == -1) {
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		return false;
	}
	
	for (pcap_if_t *d = alldevs; d != NULL; d = d->next) {
        printf("name:%s, desc:%s\n", d->name, d->description);
	}
	
	pcap_freealldevs(alldevs);
    return true;
}


bool p_create() {
	static char errbuf[PCAP_ERRBUF_SIZE + 1] = "";
    *errbuf = 0;
    
	pcap_t *fp = pcap_create(env.sniff.c_str(), errbuf);
	if (!fp) {
		fprintf(stderr, "Error in pcap_create during opening adapter `%s`: %s\n", env.sniff.c_str(), errbuf);
		return false;
	}
    env.fp = fp;
    env.needclose = true;
    return true;
}

bool p_snap() {
    bool ok = (pcap_set_snaplen(env.fp, env.snaplen) == 0);
    if (!ok) {
        fprintf(stderr, "pcap_set_snaplen error: %s\n", pcap_geterr(env.fp));
    }
    return ok;
}
bool p_timeout() {
    bool ok = (pcap_set_timeout(env.fp, env.timeout) == 0);
    if (!ok) {
        fprintf(stderr, "pcap_set_timeout error: %s\n", pcap_geterr(env.fp));
    }
    return ok;
}
bool p_promisc() {
    bool ok = (pcap_set_promisc(env.fp, env.promisc) == 0);
    if (!ok) {
        fprintf(stderr, "pcap_set_promisc error: %s\n", pcap_geterr(env.fp));
    }
    return ok;
}
bool p_bufsize() {
    bool ok = (pcap_set_buffer_size(env.fp, env.bufsize) == 0);
    if (!ok) {
        fprintf(stderr, "pcap_set_buffer_size error: %s\n", pcap_geterr(env.fp));
    }
    return ok;
}

bool p_help() {
    for (Env::fnmap::iterator it = env.fn.begin(); it != env.fn.end(); ++it) {
        cout << it->first << '\n';
    }
    return true;
}

bool p_nonblock() {
    char errbuf[PCAP_ERRBUF_SIZE + 1] = "";
    bool ok = (pcap_setnonblock(env.fp, 1, errbuf) == 0);
    if (!ok) {
        fprintf(stderr, "pcap_setnonblock error: %s\n", errbuf);
    }
    return ok;
}

bool p_activate() {
    int ret = pcap_activate(env.fp);
    if (ret == PCAP_WARNING_PROMISC_NOTSUP || ret == PCAP_WARNING) {
        fprintf(stderr, "Warning in pcap_activate during opening adapter: %s [Note: adapter was opened]\n", pcap_geterr(env.fp));
        ret = 0;
    }
    if (ret != 0) {
        fprintf(stderr, "Error in pcap_activate during opening adapter %s\n", pcap_geterr(env.fp));
    }
    return ret == 0;
}

bool p_filter() {
#ifndef PCAP_NETMASK_UNKNOWN
#define PCAP_NETMASK_UNKNOWN 0xffffff
#endif
    bpf_program filterCompiled;
    bool ok = (pcap_compile(env.fp, &filterCompiled, env.filter.c_str(), env.optimize, PCAP_NETMASK_UNKNOWN) == 0);
    if (!ok) {
        fprintf(stderr, "pcap_compile error: %s\n", pcap_geterr(env.fp));
        return ok;
    }
    ok = (pcap_setfilter(env.fp, &filterCompiled) == 0);
    if (!ok) {
        fprintf(stderr, "pcap_setfilter error: %s\n", pcap_geterr(env.fp));
    }
    return ok;
}

struct Stats {
    map<pair<unsigned,unsigned>,int> wclenCnt;
    long last;
    long long bytes;
	int total;
	Stats() { last = 0; bytes = 0; total = 0; }
    
    void show() {
        bool anyDiff = false;
        unsigned mw = 0, mc = 0;
        int cnt = 0;
        vector<pair<int,pair<unsigned,unsigned> > > v;
        v.reserve(wclenCnt.size());
        for (map<pair<unsigned,unsigned>,int>::iterator it = wclenCnt.begin(); it != wclenCnt.end(); ++it) {
            anyDiff = anyDiff || (it->first.first != it->first.second);
            mw = max(mw, it->first.first);
            mc = max(mc, it->first.second);
            cnt += it->second;
            v.push_back(make_pair(it->second, it->first));
        }
        sort(v.begin(), v.end());
        static const char *pref = " KMGTPY";
        const char *p = pref;
        bytes /= 5;
        while (bytes >= 1024 && *p) {
            p++;
            bytes /= 1024;
        }
        fprintf(stderr, "%d%cB/s,%s,mw=%u,mc=%u,cnt=%d\n", (int) bytes, *p, (anyDiff?"":"w==c for all"), mw, mc, cnt);
        for (size_t i = 0; i < 4 && i < v.size(); i++) {
            fprintf(stderr, " (%u,%u):%d\n", v[i].second.first, v[i].second.second, v[i].first);
        }
        
        bytes = 0;
        wclenCnt.clear();
    }
};

void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *data) {
    Stats &stats = *(Stats *) param;
    ++stats.wclenCnt[make_pair(header->len,header->caplen)];
    if (header->ts.tv_sec > stats.last + 4) {
        stats.show();
        stats.last = header->ts.tv_sec;
    }
    stats.bytes += header->len;
	stats.total++;
}

bool p_dispatch() {
    Stats stats;
    fprintf(stderr, "entering dispatch loop\n");
    while (stats.total < 10000) {
        int ret = pcap_dispatch(env.fp, -1, packet_handler, (u_char *) &stats);
        if (ret == -1) {
            fprintf(stderr, "\npcap_dispatch error: %s\n", pcap_geterr(env.fp));
        } else if (ret == -2) {
            fprintf(stderr, "\npcap_dispatch: break_loop called\n");
        }
        if (ret < 0) {
            return false;
        }
#ifdef __linux__
        sleep(1);
#else
		Sleep(1);
#endif
    }
    fprintf(stderr, "\n");
    return true;
}

int main(int argc, char **argv) {
    #define deffun(funname) env.fn[#funname] = p_ ## funname
        deffun(fdevs);
        deffun(create);
        deffun(snap);
        deffun(help);
        deffun(promisc);
        deffun(bufsize);
        deffun(timeout);
        deffun(activate);
        deffun(nonblock);
        deffun(filter);
        deffun(dispatch);
    #undef deffun
    
    for (int i = 1; *++argv; i++) {
        Env::fnmap::iterator it = env.fn.find(*argv);
        if (it == env.fn.end()) {
            cerr << "unknown arg: '" << *argv << "'\n";
            return -1;
        }
        bool ok = it->second();
        if (!ok) {
            cerr << "error for arg: '" << *argv << "'\n";
            return 1;
        }
    }
    if (env.needclose) {
        pcap_close(env.fp);
    }
    return 0;
}
