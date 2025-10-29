// io_inventory_pretty.cpp
// Інвентаризація I/O на macOS у табличному форматі.
// Тепер читає MMIO також з "IODeviceMemory" (для AppleARMIODevice тощо).

#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>
#include <IOKit/IOKitKeys.h>

#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include <cstdint>
#include <cstring>

using namespace std;

struct Row {
    string device;
    string ports;
    vector<pair<uint64_t,uint64_t>> ranges; // {base,end}
    string irq;
    string note;
};

// ---------- CF утиліти ----------

static string cf2str(CFStringRef s){
    if(!s) return "";
    CFIndex len = CFStringGetLength(s);
    CFIndex max = CFStringGetMaximumSizeForEncoding(len, kCFStringEncodingUTF8);
    string out; out.resize(max + 1);
    if(CFStringGetCString(s, out.data(), out.size(), kCFStringEncodingUTF8)){
        out.resize(strlen(out.c_str()));
        return out;
    }
    return "";
}

static bool cf_get_u32(CFTypeRef v, uint32_t& out){
    if(!v) return false;
    CFTypeID tid = CFGetTypeID(v);
    if(tid == CFNumberGetTypeID()){
        return CFNumberGetValue((CFNumberRef)v, kCFNumberSInt32Type, &out);
    } else if(tid == CFDataGetTypeID()){
        CFDataRef d = (CFDataRef)v;
        if(CFDataGetLength(d) < 4) return false;
        uint32_t tmp = 0;
        memcpy(&tmp, CFDataGetBytePtr(d), 4);
        out = tmp;
        return true;
    }
    return false;
}

static bool cf_get_u64(CFTypeRef v, uint64_t& out){
    if(!v) return false;
    CFTypeID tid = CFGetTypeID(v);
    if(tid == CFNumberGetTypeID()){
        return CFNumberGetValue((CFNumberRef)v, kCFNumberSInt64Type, &out);
    } else if(tid == CFDataGetTypeID()){
        CFDataRef d = (CFDataRef)v;
        if(CFDataGetLength(d) < 8) return false;
        uint64_t tmp = 0;
        memcpy(&tmp, CFDataGetBytePtr(d), 8);
        out = tmp;
        return true;
    }
    return false;
}

static string pciIdString(CFDictionaryRef props){
    if(!props) return "";
    CFTypeRef ven = (CFTypeRef)CFDictionaryGetValue(props, CFSTR("vendor-id"));
    CFTypeRef dev = (CFTypeRef)CFDictionaryGetValue(props, CFSTR("device-id"));
    uint32_t v=0, d=0;
    if(!cf_get_u32(ven, v) || !cf_get_u32(dev, d)) return "";
    stringstream ss;
    ss << std::hex << std::uppercase
       << setw(4) << setfill('0') << (v & 0xFFFF)
       << ":" << setw(4) << setfill('0') << (d & 0xFFFF);
    return ss.str();
}

// ---------- MMIO парсинг ----------

static uint32_t load_u32(const uint8_t* p){ uint32_t x; memcpy(&x,p,4); return x; }

static vector<pair<uint64_t,uint64_t>> parseAssignedOrReg(CFDataRef data){
    vector<pair<uint64_t,uint64_t>> r;
    if(!data) return r;
    const uint8_t* p = CFDataGetBytePtr(data);
    CFIndex n = CFDataGetLength(data);

    if(n % 16 == 0){
        for(CFIndex i=0; i+16<=n; i+=16){
            uint32_t md = load_u32(p+i+4);
            uint32_t lo = load_u32(p+i+8);
            uint32_t sz = load_u32(p+i+12);
            if(sz==0) continue;
            uint64_t base = ((uint64_t)md<<32) | lo;
            uint64_t end  = base + (uint64_t)sz - 1ULL;
            r.push_back({base,end});
        }
    } else if(n % 12 == 0){
        for(CFIndex i=0; i+12<=n; i+=12){
            uint32_t md = load_u32(p+i+0);
            uint32_t lo = load_u32(p+i+4);
            uint32_t sz = load_u32(p+i+8);
            if(sz==0) continue;
            uint64_t base = ((uint64_t)md<<32) | lo;
            uint64_t end  = base + (uint64_t)sz - 1ULL;
            r.push_back({base,end});
        }
    }
    return r;
}

// NEW: парсер IODeviceMemory (масив словників з "address"/"length")
static vector<pair<uint64_t,uint64_t>> parseIODeviceMemory(CFTypeRef prop){
    vector<pair<uint64_t,uint64_t>> r;
    if(!prop) return r;
    if(CFGetTypeID(prop) != CFArrayGetTypeID()) return r;

    CFArrayRef arr = (CFArrayRef)prop;
    CFIndex n = CFArrayGetCount(arr);
    for(CFIndex i=0;i<n;i++){
        CFTypeRef item = CFArrayGetValueAtIndex(arr, i);
        if(!item || CFGetTypeID(item)!=CFDictionaryGetTypeID()) continue;
        CFDictionaryRef d = (CFDictionaryRef)item;

        CFTypeRef a = CFDictionaryGetValue(d, CFSTR("address"));
        CFTypeRef l = CFDictionaryGetValue(d, CFSTR("length"));
        uint64_t addr=0,len=0;
        if(cf_get_u64(a, addr) && cf_get_u64(l, len) && len){
            r.push_back({addr, addr + len - 1ULL});
            continue;
        }

        // інколи є як CFData по 16 байт (addr hi/lo + len hi/lo)
        CFTypeRef ad = CFDictionaryGetValue(d, CFSTR("Address"));
        CFTypeRef ld = CFDictionaryGetValue(d, CFSTR("Length"));
        if(ad && ld && CFGetTypeID(ad)==CFDataGetTypeID() && CFGetTypeID(ld)==CFDataGetTypeID()){
            CFDataRef A=(CFDataRef)ad, L=(CFDataRef)ld;
            if(CFDataGetLength(A)>=8 && CFDataGetLength(L)>=8){
                uint64_t a64=0,l64=0;
                memcpy(&a64, CFDataGetBytePtr(A), 8);
                memcpy(&l64, CFDataGetBytePtr(L), 8);
                if(l64) r.push_back({a64, a64 + l64 - 1ULL});
            }
        }
    }
    return r;
}

static string irqInfo(CFDictionaryRef props){
    if(!props) return "";
    CFTypeRef specAny = CFDictionaryGetValue(props, CFSTR("IOInterruptSpecifiers"));
    if(!specAny) return "";
    CFIndex bytes = 0;
    if(CFGetTypeID(specAny) == CFDataGetTypeID()){
        bytes = CFDataGetLength((CFDataRef)specAny);
    } else if(CFGetTypeID(specAny) == CFArrayGetTypeID()){
        bytes = (CFIndex)CFArrayGetCount((CFArrayRef)specAny); // count як індикатор
    }
    CFStringRef ctrl = (CFStringRef)CFDictionaryGetValue(props, CFSTR("IOInterruptController"));
    string c = cf2str(ctrl);
    stringstream ss;
    ss << "Spec:" << (long)bytes << (CFGetTypeID(specAny)==CFDataGetTypeID()?"B":" item(s)");
    if(!c.empty()) ss << ", " << c;
    return ss.str();
}

static string prettyName(io_registry_entry_t e, CFDictionaryRef props, const string& ioClass){
    vector<CFStringRef> keys = {
        CFSTR("IOName"), CFSTR("USB Product Name"), CFSTR("USB Product Name Override"),
        CFSTR("product-name"), CFSTR("model"), CFSTR("name")
    };
    for(auto k: keys){
        CFTypeRef v = CFDictionaryGetValue(props, k);
        if(v && CFGetTypeID(v)==CFStringGetTypeID()){
            string s = cf2str((CFStringRef)v);
            if(!s.empty()){
                if(ioClass=="IOPCIDevice"){
                    string pid = pciIdString(props);
                    if(!pid.empty()) s += " [" + pid + "]";
                }
                return s;
            }
        }
    }
    return ioClass;
}

// ---------- IORegistry обход ----------

static void collect(const char* klass, vector<Row>& out, const string& noteTag){
    CFMutableDictionaryRef match = IOServiceMatching(klass);
    if(!match) return;
    io_iterator_t it = 0;
    if(IOServiceGetMatchingServices(kIOMainPortDefault, match, &it) != KERN_SUCCESS) return;

    io_registry_entry_t o;
    while((o = IOIteratorNext(it))){
        CFMutableDictionaryRef props = nullptr;
        if(IORegistryEntryCreateCFProperties(o, &props, kCFAllocatorDefault,
                                             kIORegistryIterateRecursively) != KERN_SUCCESS){
            IOObjectRelease(o);
            continue;
        }
        CFStringRef clsRef = IOObjectCopyClass(o);
        string ioClass = cf2str(clsRef); if(clsRef) CFRelease(clsRef);

        Row row;
        row.device = prettyName(o, props, ioClass);
        if(row.device.empty()) row.device = ioClass;
        row.ports  = "N/A";

        // MMIO: assigned-addresses → reg → IODeviceMemory
        CFDataRef aa = (CFDataRef)CFDictionaryGetValue(props, CFSTR("assigned-addresses"));
        CFDataRef rg = (CFDataRef)CFDictionaryGetValue(props, CFSTR("reg"));
        auto v1 = parseAssignedOrReg(aa);
        auto v2 = parseAssignedOrReg(rg);
        if(!v1.empty()) row.ranges = v1;
        else if(!v2.empty()) row.ranges = v2;
        else {
            CFTypeRef iom = CFDictionaryGetValue(props, CFSTR("IODeviceMemory"));
            auto v3 = parseIODeviceMemory(iom);
            if(!v3.empty()) row.ranges = v3;
        }

        row.irq = irqInfo(props);
        if(row.irq.empty()) row.irq = "N/A";

        if(noteTag=="PCIe") row.note = "Bus Mastering (MSI)";
        else if(noteTag=="USB-Controller") row.note = "Bus Mastering (через DART)";
        else if(noteTag=="USB") row.note = "USB пристрій";
        else if(noteTag=="Audio") row.note = "Аудіо контролер";
        else if(noteTag=="I2C") row.note = "Системний IO";
        else if(noteTag=="SoC-IO") row.note = "Системний IO";
        else row.note = noteTag;

        if(props) CFRelease(props);
        IOObjectRelease(o);
        out.push_back(row);
    }
    IOObjectRelease(it);
}

// ---------- друк таблиці ----------

static string hex64(uint64_t v){
    stringstream ss; ss << "0x" << std::hex << std::nouppercase << v;
    return ss.str();
}

static void printDivider(size_t w1,size_t w2,size_t w3,size_t w4,size_t w5){
    auto rep=[](char ch,size_t n){ for(size_t i=0;i<n;i++) cout<<ch; };
    cout<<"+";
    rep('-',w1+2); cout<<"+";
    rep('-',w2+2); cout<<"+";
    rep('-',w3+2); cout<<"+";
    rep('-',w4+2); cout<<"+";
    rep('-',w5+2); cout<<"+\n";
}

static void printRowWrapped(const Row& r,
                            size_t w1,size_t w2,size_t w3,size_t w4,size_t w5)
{
    vector<string> memLines;
    if(r.ranges.empty()) memLines.push_back("—");
    else{
        for(auto &p: r.ranges){
            string s = hex64(p.first) + " \xE2\x80\x93 " + hex64(p.second);
            memLines.push_back(s);
        }
    }
    size_t lines = max<size_t>(1, memLines.size());

    for(size_t i=0;i<lines;i++){
        cout<<"| "<<setw(w1)<<left<<(i==0? r.device:"")
            <<" | "<<setw(w2)<<left<<(i==0? r.ports :"")
            <<" | "<<setw(w3)<<left<<(i<memLines.size()? memLines[i] :"")
            <<" | "<<setw(w4)<<left<<(i==0? r.irq :"")
            <<" | "<<setw(w5)<<left<<(i==0? r.note:"")<<" |\n";
    }
}

int main(){
    vector<Row> rows;

    collect("IOPCIDevice", rows, "PCIe");
    collect("AppleUSBXHCI", rows, "USB-Controller");
    collect("IOUSBHostDevice", rows, "USB");
    collect("AppleHDAController", rows, "Audio");
    collect("AppleT8103Audio", rows, "Audio");
    collect("AppleI2CController", rows, "I2C");
    collect("AppleARMIODevice", rows, "SoC-IO");
    collect("AppleSPU", rows, "SoC-IO");

    const size_t W1=30, W2=5, W3=34, W4=22, W5=26;

    printDivider(W1,W2,W3,W4,W5);
    cout<<"| "<<setw(W1)<<left<<"Device"
        <<" | "<<setw(W2)<<left<<"Port"
        <<" | "<<setw(W3)<<left<<"Memory Range"
        <<" | "<<setw(W4)<<left<<"IRQ"
        <<" | "<<setw(W5)<<left<<"Примітка"<<" |\n";
    printDivider(W1,W2,W3,W4,W5);

    for(const auto& r : rows){
        printRowWrapped(r, W1,W2,W3,W4,W5);
        printDivider(W1,W2,W3,W4,W5);
    }
    return 0;
}
