export interface Vulnerability {
  number: number;
  title: string;
  severity: "Low" | "Medium" | "High" | "Critical";
  summary: string;
  code: string;
  do: string;
  dont: string;
  category?: string;
}

export const vulnerabilities: Vulnerability[] = [
  // Level 1 – Basics (Low/Medium Severity)
  {
    number: 1,
    title: "Stack Buffer Overflow",
    severity: "Low",
    summary: "Input > 8 bytes → overwrite memory",
    code: "char buf[8];\ngets(buf);",
    do: "Use fgets/strncpy; validate input",
    dont: "Use gets/strcpy",
    category: "Memory Safety"
  },
  {
    number: 2,
    title: "Hardcoded Secrets",
    severity: "Medium",
    summary: "Firmware dump reveals keys",
    code: "const char api_key[] = \"123456789\";",
    do: "Use secure element/hardware keys",
    dont: "Hardcode secrets",
    category: "Authentication"
  },
  {
    number: 3,
    title: "Off-by-One Error",
    severity: "Low",
    summary: "Writes past buffer → memory corruption",
    code: "for(int i=0;i<=16;i++) buf[i]=src[i];",
    do: "Use < bounds checks",
    dont: "Assume <= safe",
    category: "Memory Safety"
  },
  {
    number: 4,
    title: "Simple Logic Bug",
    severity: "Medium",
    summary: "Wrong role logic → privilege escalation",
    code: "bool is_admin(int r){return r!=0;}",
    do: "Explicit role checks",
    dont: "Assume non-zero=admin",
    category: "Access Control"
  },
  {
    number: 5,
    title: "Null Pointer Deref",
    severity: "Low",
    summary: "Crash/DoS",
    code: "char *p=NULL; strcpy(p,\"a\");",
    do: "Check pointers",
    dont: "Use uninitialized pointers",
    category: "Memory Safety"
  },
  {
    number: 6,
    title: "Improper Default Config",
    severity: "Medium",
    summary: "Debug mode in production",
    code: "bool debug=true;",
    do: "Disable debug for prod",
    dont: "Ship debug builds",
    category: "Configuration"
  },
  {
    number: 7,
    title: "Array Index Overflow",
    severity: "Low",
    summary: "Invalid index → corruption",
    code: "arr[index]=v;",
    do: "Validate index ranges",
    dont: "Trust external index",
    category: "Memory Safety"
  },
  {
    number: 8,
    title: "Improper Input Sanitization",
    severity: "Medium",
    summary: "Injection/overflow",
    code: "strcpy(buf,user_input);",
    do: "Sanitize inputs",
    dont: "Assume input safe",
    category: "Input Validation"
  },
  {
    number: 9,
    title: "Missing Null Termination",
    severity: "Low",
    summary: "Non-terminated string → overflow",
    code: "char b[8]; strncpy(b,in,8);",
    do: "Always null-terminate",
    dont: "Assume strncpy sets terminator",
    category: "Memory Safety"
  },
  {
    number: 10,
    title: "Uninitialized Variables",
    severity: "Low",
    summary: "Random behavior",
    code: "int s; if(s==1){}",
    do: "Initialize variables",
    dont: "Trust compiler init",
    category: "Memory Safety"
  },
  {
    number: 11,
    title: "Weak RNG",
    severity: "Medium",
    summary: "Predictable tokens",
    code: "rand()%100",
    do: "Use CSPRNG",
    dont: "Use rand() for secrets",
    category: "Cryptography"
  },
  {
    number: 12,
    title: "Stack Memory Leak",
    severity: "Low",
    summary: "Sensitive data left in memory",
    code: "char buf[32]; // no zeroing",
    do: "Zero buffers after use",
    dont: "Leave secrets in RAM",
    category: "Memory Safety"
  },
  {
    number: 13,
    title: "Unchecked Sensor Input",
    severity: "Medium",
    summary: "Sensor spoofing",
    code: "if(sensor>0) act();",
    do: "Validate sensor range",
    dont: "Act on raw sensor directly",
    category: "Input Validation"
  },
  {
    number: 14,
    title: "Unsafe Type Casting",
    severity: "Low",
    summary: "Truncation/overflow",
    code: "uint16_t len; memcpy(buf,data,(int)len);",
    do: "Use correct types & bounds",
    dont: "Blind casts",
    category: "Memory Safety"
  },
  {
    number: 15,
    title: "Insecure Default Password",
    severity: "Medium",
    summary: "Default creds exploited",
    code: "#define DEFAULT_PW \"admin\"",
    do: "Force password change",
    dont: "Ship defaults",
    category: "Authentication"
  },
  {
    number: 16,
    title: "Debug Logging Secrets",
    severity: "Medium",
    summary: "Secrets leaked over logs",
    code: "printf(\"key=%s\", key);",
    do: "Avoid logging secrets",
    dont: "Log keys in production",
    category: "Information Disclosure"
  },
  {
    number: 17,
    title: "Missing Return Checks",
    severity: "Low",
    summary: "Unhandled failures",
    code: "fopen(file,\"r\");",
    do: "Check return values",
    dont: "Ignore errors",
    category: "Error Handling"
  },
  {
    number: 18,
    title: "Improper Array Copy",
    severity: "Low",
    summary: "Copy larger than dest",
    code: "memcpy(dest,src,len);",
    do: "Validate sizes",
    dont: "Blind memcpy",
    category: "Memory Safety"
  },
  {
    number: 19,
    title: "Hardcoded UART Baud",
    severity: "Low",
    summary: "Predictable comm",
    code: "uart_init(9600);",
    do: "Allow configurable baud",
    dont: "Hardcode comm params",
    category: "Configuration"
  },
  {
    number: 20,
    title: "Unchecked ADC Input",
    severity: "Medium",
    summary: "Spoofed sensor triggers",
    code: "adc_val=read_adc();",
    do: "Validate ADC readings",
    dont: "Trust ADC blindly",
    category: "Input Validation"
  },
  {
    number: 21,
    title: "Improper Null-Termination",
    severity: "Low",
    summary: "Missing terminator → overflow",
    code: "char b[8]; strncpy(b,in,8);",
    do: "Ensure terminator",
    dont: "Rely on strncpy",
    category: "Memory Safety"
  },
  {
    number: 22,
    title: "Stack Smashing via Recursion",
    severity: "Medium",
    summary: "Stack overflow crash",
    code: "void r(){r();}",
    do: "Limit recursion",
    dont: "Unbounded recursion",
    category: "Memory Safety"
  },
  {
    number: 23,
    title: "Unsafe Global Vars",
    severity: "Low",
    summary: "Race conditions",
    code: "int counter;",
    do: "Protect globals",
    dont: "Use globals without sync",
    category: "Concurrency"
  },
  {
    number: 24,
    title: "Missing UART Validation",
    severity: "Medium",
    summary: "Arbitrary input → overflow",
    code: "uart_read(buf);",
    do: "Validate UART input",
    dont: "Trust serial data",
    category: "Input Validation"
  },
  {
    number: 25,
    title: "Unsafe Pointer Arithmetic",
    severity: "Low",
    summary: "Corrupt memory",
    code: "char *p = buf+offset;",
    do: "Validate offsets",
    dont: "Blind arithmetic",
    category: "Memory Safety"
  },

  // Level 2 – Intermediate (Medium/High Severity)
  {
    number: 26,
    title: "Insecure Packet Parsing",
    severity: "High",
    summary: "Oversized packet → overflow",
    code: "if(len<512) memcpy(buf,pkt,len);",
    do: "Ensure len<=buf",
    dont: "Trust protocol length",
    category: "Input Validation"
  },
  {
    number: 27,
    title: "Format String Vulnerability",
    severity: "High",
    summary: "Leak or write memory via format",
    code: "printf(msg);",
    do: "printf('%s',msg)",
    dont: "Pass user as format",
    category: "Input Validation"
  },
  {
    number: 28,
    title: "Weak Crypto (XOR)",
    severity: "Medium",
    summary: "Reversible encryption",
    code: "for(i=0;i<len;i++) data[i]^=0x42;",
    do: "Use AES/ChaCha",
    dont: "DIY crypto",
    category: "Cryptography"
  },
  {
    number: 29,
    title: "Serial Input Exec",
    severity: "High",
    summary: "Command injection",
    code: "system(input);",
    do: "Whitelist commands",
    dont: "Execute raw input",
    category: "Command Injection"
  },
  {
    number: 30,
    title: "Insecure Firmware Update",
    severity: "High",
    summary: "MITM firmware injection",
    code: "boot(new_fw);",
    do: "Verify signatures",
    dont: "Boot unverified fw",
    category: "Firmware Security"
  },
  {
    number: 31,
    title: "Weak Session Token",
    severity: "Medium",
    summary: "Guessable token",
    code: "char tok[8]=\"12345678\";",
    do: "CSPRNG tokens",
    dont: "Hardcode tokens",
    category: "Authentication"
  },
  {
    number: 32,
    title: "UART Buffer Overflow",
    severity: "High",
    summary: "Overflow via long stream",
    code: "while(uart_read(&c)) buf[i++]=c;",
    do: "Limit reads",
    dont: "Trust continuous streams",
    category: "Memory Safety"
  },
  {
    number: 33,
    title: "Improper Access Control",
    severity: "Medium",
    summary: "Naive access check",
    code: "if(user_id>0) access();",
    do: "RBAC/ACL checks",
    dont: "Trust simple checks",
    category: "Access Control"
  },
  {
    number: 34,
    title: "Shared Resource Conflict",
    severity: "Medium",
    summary: "Race corrupts data",
    code: "adc_read(); spi_write();",
    do: "Mutex/semaphore",
    dont: "Assume single-task",
    category: "Concurrency"
  },
  {
    number: 35,
    title: "Firmware Rollback",
    severity: "High",
    summary: "Downgrade to vulnerable fw",
    code: "boot(prev_fw);",
    do: "Enforce min version",
    dont: "Allow rollbacks",
    category: "Firmware Security"
  },
  {
    number: 36,
    title: "Race Condition File Access",
    severity: "Medium",
    summary: "Inconsistent logs",
    code: "write_log();read_log();",
    do: "File locks",
    dont: "Concurrent writes",
    category: "Concurrency"
  },
  {
    number: 37,
    title: "Hardcoded Endpoint",
    severity: "Medium",
    summary: "Targetable endpoint",
    code: "const url='http://1.2.3.4';",
    do: "Configurable endpoints",
    dont: "Hardcode network targets",
    category: "Configuration"
  },
  {
    number: 38,
    title: "Memory Alignment Error",
    severity: "Medium",
    summary: "Misaligned access crash",
    code: "uint32_t* p=(uint32_t*)buf;",
    do: "Align buffers",
    dont: "Ignore alignment",
    category: "Memory Safety"
  },
  {
    number: 39,
    title: "Unprotected Bootloader",
    severity: "High",
    summary: "Flash bypass",
    code: "bootloader();",
    do: "Lock bootloader",
    dont: "Debug boot open",
    category: "Firmware Security"
  },
  {
    number: 40,
    title: "Missing Watchdog",
    severity: "Medium",
    summary: "Device hangs",
    code: "while(1){}",
    do: "Enable watchdog",
    dont: "Assume infinite loops safe",
    category: "System Integrity"
  },
  {
    number: 41,
    title: "Poor Exception Handling",
    severity: "Medium",
    summary: "Unhandled edge cases",
    code: "try{}catch(...){ }",
    do: "Handle errors explicitly",
    dont: "Catch-all empty",
    category: "Error Handling"
  },
  {
    number: 42,
    title: "Insecure UART Config",
    severity: "High",
    summary: "Open debug port",
    code: "uart_init();",
    do: "Lock serial in prod",
    dont: "Leave UART open",
    category: "Configuration"
  },
  {
    number: 43,
    title: "Unprotected Flash Sectors",
    severity: "High",
    summary: "Overwrite boot code",
    code: "flash_write(addr,data);",
    do: "Protect flash sectors",
    dont: "Write critical regions",
    category: "Firmware Security"
  },
  {
    number: 44,
    title: "Peripheral Sleep Race",
    severity: "Medium",
    summary: "Access before ready",
    code: "periph_enable(); periph_write();",
    do: "Wait ready flag",
    dont: "Assume instant ready",
    category: "Hardware Interface"
  },
  {
    number: 45,
    title: "Power Management Bypass",
    severity: "High",
    summary: "Unlock on wake",
    code: "sleep/wake bypass auth",
    do: "Re-authenticate on wake",
    dont: "Skip checks on low-power",
    category: "Power Management"
  },

  // Level 3 – Complex/System-Level (High Severity)
  {
    number: 46,
    title: "Fault Injection Vulnerability",
    severity: "High",
    summary: "Glitch bypasses auth",
    code: "if(check_auth()) access();",
    do: "Redundant checks/tamper detect",
    dont: "Single guard",
    category: "Physical Security"
  },
  {
    number: 47,
    title: "Weak OTA Verification (CRC)",
    severity: "High",
    summary: "CRC bypass",
    code: "verify_crc(fw);",
    do: "Use signatures",
    dont: "Rely on CRC",
    category: "Firmware Security"
  },
  {
    number: 48,
    title: "Factory Debug Backdoor",
    severity: "High",
    summary: "Hidden backdoor",
    code: "if(strcmp(cmd,'FACTORY')==0) enable_admin();",
    do: "Strip debug",
    dont: "Leave backdoors",
    category: "Access Control"
  },
  {
    number: 49,
    title: "Side-Channel Power Analysis",
    severity: "High",
    summary: "Power/timing leak",
    code: "if(key[i]==b) delay(5);",
    do: "Const-time ops & masking",
    dont: "Leak via timing",
    category: "Side Channel"
  },
  {
    number: 50,
    title: "Flexible Array Stack Smash",
    severity: "High",
    summary: "Oversized pkt → overflow",
    code: "memcpy(buf,pkt->data,pkt->len);",
    do: "Validate pkt->len<=buf",
    dont: "Trust pkt len",
    category: "Memory Safety"
  },
  {
    number: 51,
    title: "Peripheral Misconfig",
    severity: "High",
    summary: "Peripheral instability",
    code: "spi_write(SPI1,data);",
    do: "Check ready flags",
    dont: "Assume config safe",
    category: "Hardware Interface"
  },
  {
    number: 52,
    title: "Voltage Glitch Unlock",
    severity: "High",
    summary: "Power interrupt bypass",
    code: "if(auth_ok) unlock();",
    do: "Glitch countermeasures",
    dont: "Assume stable power",
    category: "Physical Security"
  },
  {
    number: 53,
    title: "DMA Misconfig",
    severity: "High",
    summary: "Out-of-bounds DMA",
    code: "dma_start(buf);",
    do: "Validate DMA regions",
    dont: "Blind DMA",
    category: "Hardware Interface"
  },
  {
    number: 54,
    title: "I2C Address Conflict",
    severity: "High",
    summary: "Address collision",
    code: "i2c_set_addr(0x50);",
    do: "Detect conflicts",
    dont: "Assume uniqueness",
    category: "Hardware Interface"
  },
  {
    number: 55,
    title: "Flash Wear Misuse",
    severity: "High",
    summary: "Wear-out of critical sectors",
    code: "flash_write(addr,data);",
    do: "Wear-leveling",
    dont: "Constant writes to same addr",
    category: "Hardware Interface"
  },
  {
    number: 56,
    title: "Boot-Time Side Channel",
    severity: "High",
    summary: "Power/timing leak on boot",
    code: "read_key();",
    do: "Mask ops at boot",
    dont: "Expose keys early",
    category: "Side Channel"
  },
  {
    number: 57,
    title: "Task Priority Handling",
    severity: "High",
    summary: "Starvation or inversion",
    code: "task1.priority=5;",
    do: "Manage priorities correctly",
    dont: "Ignore task design",
    category: "Concurrency"
  },
  {
    number: 58,
    title: "Stack Overflow via Recursion",
    severity: "High",
    summary: "Stack exhaustion",
    code: "void r(){r();}",
    do: "Avoid deep recursion",
    dont: "Unbounded recursion",
    category: "Memory Safety"
  },
  {
    number: 59,
    title: "Weak Bootloader Auth",
    severity: "High",
    summary: "Guess keys",
    code: "boot_auth(key);",
    do: "Strong signature auth",
    dont: "Weak boot auth",
    category: "Firmware Security"
  },
  {
    number: 60,
    title: "RTC Tampering",
    severity: "High",
    summary: "Adjust RTC to bypass",
    code: "if(rtc>expiry) unlock();",
    do: "Cross-check RTC",
    dont: "Trust RTC blindly",
    category: "Physical Security"
  },
  {
    number: 61,
    title: "Multi-Peripheral Conflict",
    severity: "High",
    summary: "Bus conflict",
    code: "spi_write(); i2c_read();",
    do: "Serialize access",
    dont: "Assume isolation",
    category: "Hardware Interface"
  },
  {
    number: 62,
    title: "PWM Misconfig",
    severity: "High",
    summary: "Motor damage",
    code: "pwm_set(duty);",
    do: "Validate duty",
    dont: "Blind values",
    category: "Hardware Interface"
  },
  {
    number: 63,
    title: "Hardcoded CAN ID",
    severity: "High",
    summary: "CAN spoofing",
    code: "can_send(0x123,data);",
    do: "ID filtering",
    dont: "Predictable IDs",
    category: "Network Security"
  },
  {
    number: 64,
    title: "Task Deadlock",
    severity: "High",
    summary: "System deadlock",
    code: "mutex1.lock(); mutex2.lock();",
    do: "Avoid circular locks",
    dont: "Ignore lock ordering",
    category: "Concurrency"
  },
  {
    number: 65,
    title: "Improper Timer Usage",
    severity: "High",
    summary: "Wrap-around errors",
    code: "if(timer_expired) act();",
    do: "Use robust timers",
    dont: "Assume infinite timer",
    category: "System Integrity"
  },
  {
    number: 66,
    title: "Heap Fragmentation",
    severity: "High",
    summary: "OOM/fragmentation",
    code: "malloc/free many small blocks",
    do: "Use pools",
    dont: "Unbounded alloc patterns",
    category: "Memory Safety"
  },
  {
    number: 67,
    title: "Peripheral Sleep/Wake Exploit",
    severity: "High",
    summary: "Access pre-ready",
    code: "if(periph_ready) access();",
    do: "Wait ready",
    dont: "Assume ready",
    category: "Hardware Interface"
  },
  {
    number: 68,
    title: "Unverified Peripheral Firmware",
    severity: "High",
    summary: "Malicious periph fw",
    code: "periph_fw_load();",
    do: "Verify signatures",
    dont: "Load untrusted fw",
    category: "Firmware Security"
  },
  {
    number: 69,
    title: "Improper Mutex Handling",
    severity: "High",
    summary: "Forgotten unlock",
    code: "mutex.lock(); critical();",
    do: "Use RAII/patterns",
    dont: "Assume unlock always runs",
    category: "Concurrency"
  },
  {
    number: 70,
    title: "Memory Alignment Errors",
    severity: "High",
    summary: "Crash on misalign",
    code: "uint32_t* p=(uint32_t*)buf;",
    do: "Align buffers",
    dont: "Cast blindly",
    category: "Memory Safety"
  },

  // Level 4 – Advanced/Elite (Critical Severity)
  {
    number: 71,
    title: "Timing Attack on Password Check",
    severity: "Critical",
    summary: "Byte-by-byte extraction via timing",
    code: "for(i=0;i<strlen(pw);i++) if(input[i]!=pw[i]) return false;",
    do: "Constant-time compare",
    dont: "Early return on mismatch",
    category: "Side Channel"
  },
  {
    number: 72,
    title: "Cache Timing Side-Channel",
    severity: "Critical",
    summary: "Cache analysis reveals secrets",
    code: "if(secret[i]) access_fast(); else access_slow();",
    do: "Data-independent access",
    dont: "Branch on secrets",
    category: "Side Channel"
  },
  {
    number: 73,
    title: "Rowhammer-like",
    severity: "Critical",
    summary: "Bitflips in adjacent rows",
    code: "dram[addr]++",
    do: "ECC/refresh defenses",
    dont: "Ignore hardware faults",
    category: "Physical Security"
  },
  {
    number: 74,
    title: "EM Side-Channel Leakage",
    severity: "Critical",
    summary: "EM capture → key recovery",
    code: "crypto_calc(key,data);",
    do: "Shield and mask",
    dont: "Expose sensitive emissions",
    category: "Side Channel"
  },
  {
    number: 75,
    title: "Clock Glitch Fault Injection",
    severity: "Critical",
    summary: "Clock glitch bypass",
    code: "if(check_auth()) access();",
    do: "Clock monitors & redundancy",
    dont: "Single check auth",
    category: "Physical Security"
  },
  {
    number: 76,
    title: "Secure Boot Bypass",
    severity: "Critical",
    summary: "Modify verif to boot unsigned",
    code: "if(sig_valid) boot();",
    do: "Immutable ROM root-of-trust",
    dont: "Weak boot chain",
    category: "Firmware Security"
  },
  {
    number: 77,
    title: "Voltage Side-Channel",
    severity: "Critical",
    summary: "Power traces leak key",
    code: "aes_encrypt(key,data);",
    do: "Add noise & masking",
    dont: "Expose clean traces",
    category: "Side Channel"
  },
  {
    number: 78,
    title: "DMA Row Attack",
    severity: "Critical",
    summary: "DMA exfiltrates secrets",
    code: "dma_copy(buf,periph,len);",
    do: "Restrict DMA ranges",
    dont: "Grant global DMA",
    category: "Hardware Interface"
  },
  {
    number: 79,
    title: "Hardware Debug Abuse",
    severity: "Critical",
    summary: "Extract firmware via JTAG",
    code: "jtag_enable();",
    do: "Disable/lock debug",
    dont: "Ship with debug enabled",
    category: "Physical Security"
  },
  {
    number: 80,
    title: "ECC Side-Channel",
    severity: "Critical",
    summary: "Leak private scalar",
    code: "ecc_mul(k,P);",
    do: "Constant-time ECC",
    dont: "Naive ECC libs",
    category: "Cryptography"
  },
  {
    number: 81,
    title: "Cold Boot Secret Recovery",
    severity: "Critical",
    summary: "Residual RAM reveals keys",
    code: "read_ram_after_reset();",
    do: "Zeroize on reset",
    dont: "Leave secrets in RAM",
    category: "Physical Security"
  },
  {
    number: 82,
    title: "Speculative Execution Leak",
    severity: "Critical",
    summary: "Spectre-like leakage",
    code: "if(i<bound) return arr[i];",
    do: "Speculation barriers",
    dont: "Assume CPU safe",
    category: "Side Channel"
  },
  {
    number: 83,
    title: "Enclave Glitching",
    severity: "Critical",
    summary: "Fault to bypass enclave",
    code: "if(enclave_ok) run();",
    do: "Defensive enclave checks",
    dont: "Single enclave gate",
    category: "Physical Security"
  },
  {
    number: 84,
    title: "Cache Flush+Reload",
    severity: "Critical",
    summary: "Cache monitor exfiltrates bits",
    code: "access_table[idx];",
    do: "Constant memory patterns",
    dont: "Key-dependent access",
    category: "Side Channel"
  },
  {
    number: 85,
    title: "Row Refresh Exploit",
    severity: "Critical",
    summary: "Neighbor bit flips",
    code: "dram_access(row);",
    do: "TRR/ECC",
    dont: "Ignore DRAM quirks",
    category: "Physical Security"
  },
  {
    number: 86,
    title: "Laser/EM Fault Injection",
    severity: "Critical",
    summary: "Flip auth bits physically",
    code: "if(sig_ok) boot();",
    do: "Tamper detection & shielding",
    dont: "Ignore physical threats",
    category: "Physical Security"
  },
  {
    number: 87,
    title: "Misused Secure Element",
    severity: "Critical",
    summary: "Incorrect APIs leak data",
    code: "se_store(key);",
    do: "Follow vendor API guidance",
    dont: "Misconfigure SE",
    category: "Hardware Security"
  },
  {
    number: 88,
    title: "Rowhammer cross-VM",
    severity: "Critical",
    summary: "Cross-VM leakage",
    code: "vm_write(addr);",
    do: "VM isolation & ECC",
    dont: "Assume virtualization safe",
    category: "Physical Security"
  },
  {
    number: 89,
    title: "Authentication Counter Glitch",
    severity: "Critical",
    summary: "Glitch bypasses lockout",
    code: "if(attempts<3) login();",
    do: "Monotonic secure counters",
    dont: "Weak attempt tracking",
    category: "Physical Security"
  },
  {
    number: 90,
    title: "Micro-architectural Covert Channel",
    severity: "Critical",
    summary: "Hidden exfil via microarch",
    code: "proc1 mod cache; proc2 read;",
    do: "Isolate sensitive tasks",
    dont: "Share microarch resources",
    category: "Side Channel"
  },
  {
    number: 91,
    title: "Boot Key Exposure via Debug",
    severity: "Critical",
    summary: "Boot secrets exposed on debug",
    code: "uart_dump_keys();",
    do: "Disable debug early",
    dont: "Expose keys via UART",
    category: "Information Disclosure"
  },
  {
    number: 92,
    title: "Tamper via Connector Exploit",
    severity: "Critical",
    summary: "Physical connector provides access",
    code: "usb_debug_enabled()",
    do: "Lock ports in prod",
    dont: "Ship open connectors",
    category: "Physical Security"
  },
  {
    number: 93,
    title: "Firmware Metadata Leak",
    severity: "Critical",
    summary: "Leak targeted version",
    code: "log_fw_version();",
    do: "Mask metadata",
    dont: "Publish exact fw details",
    category: "Information Disclosure"
  },
  {
    number: 94,
    title: "Power Management Timing Leak",
    severity: "Critical",
    summary: "Timing reveals auth",
    code: "sleep_wake_auth()",
    do: "Randomize wake ops",
    dont: "Deterministic wake paths",
    category: "Side Channel"
  },
  {
    number: 95,
    title: "Physical Bus Sniffing",
    severity: "Critical",
    summary: "Eavesdrop bus data",
    code: "snoop_spi()",
    do: "Bus encryption/auth",
    dont: "Transmit cleartext on busses",
    category: "Network Security"
  },
  {
    number: 96,
    title: "Tamper-evident Bypass",
    severity: "Critical",
    summary: "Modify tamper sensor",
    code: "if(!tamper) proceed;",
    do: "Multiple sensors & logging",
    dont: "Single sensor reliance",
    category: "Physical Security"
  },
  {
    number: 97,
    title: "Crypto RNG Exploit on Boot",
    severity: "Critical",
    summary: "Predictable RNG seeds",
    code: "seed_from_untrusted()",
    do: "Seed from entropy sources",
    dont: "Use predictable seeds",
    category: "Cryptography"
  },
  {
    number: 98,
    title: "Hardware Backdoor in Supply Chain",
    severity: "Critical",
    summary: "Persistent backdoor",
    code: "malicious_fab_logic()",
    do: "Supply chain audits",
    dont: "Assume chips trusted",
    category: "Supply Chain"
  },
  {
    number: 99,
    title: "Unprotected Secure Enclave Debugging",
    severity: "Critical",
    summary: "Extract secrets via enclave debug",
    code: "enclave_debug_on()",
    do: "Disable enclave debug",
    dont: "Allow debug in prod",
    category: "Hardware Security"
  },
  {
    number: 100,
    title: "Advanced Covert Channel via Peripherals",
    severity: "Critical",
    summary: "Stealthy exfil via peripheral timing",
    code: "modulate_periph_activity()",
    do: "Monitor anomalies",
    dont: "Allow unconstrained peripheral timing",
    category: "Side Channel"
  }
];

export const getSeverityColor = (severity: Vulnerability["severity"]) => {
  switch (severity) {
    case "Low":
      return "severity-low";
    case "Medium":
      return "severity-medium";
    case "High":
      return "severity-high";
    case "Critical":
      return "severity-critical";
    default:
      return "severity-medium";
  }
};

export const getSeverityGlowColor = (severity: Vulnerability["severity"]) => {
  switch (severity) {
    case "Low":
      return "severity-low-glow";
    case "Medium":
      return "severity-medium-glow";
    case "High":
      return "severity-high-glow";
    case "Critical":
      return "severity-critical-glow";
    default:
      return "severity-medium-glow";
  }
};