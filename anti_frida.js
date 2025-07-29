function h(){
    console.log("a");
}


function anti_maps_status() {
    var pt_strstr = Module.findExportByName("libc.so", 'strstr');
    var pt_strcmp = Module.findExportByName("libc.so", 'strcmp');
    Interceptor.attach(pt_strstr, {
        onEnter: function (args) {
            var str1 = args[0].readCString();
            var str2 = args[1].readCString();
            if (str2.indexOf("agent") !== -1  || str2.indexOf("frida") !== -1 || str2.indexOf("gmain") !== -1 || str2.indexOf("gum-js-loop") !== -1 || str2.indexOf("pool-frida") !== -1 || str2.indexOf("gdbus") !== -1) {
                this.hook = true;
            }
        },
        onLeave: function (retval) {
            if (this.hook) {
                retval.replace(0);
            }
        }
    });

    Interceptor.attach(pt_strcmp, {
        onEnter: function (args) {
            var str1 = args[0].readCString();
            var str2 = args[1].readCString();
            if (str2.indexOf("REJECT") !== -1  || str2.indexOf("frida") !== -1) {
                this.hook = true;
            }
        },
        onLeave: function (retval) {
            if (this.hook) {
                retval.replace(0);
            }
        }
    });
}

function mapsRedirect() {
    var FakeMaps = "/data/data/com.zj.wuaipojie/maps";
    const openPtr = Module.getExportByName('libc.so', 'open');
    const open = new NativeFunction(openPtr, 'int', ['pointer', 'int']);
    var readPtr = Module.findExportByName("libc.so", "read");
    var read = new NativeFunction(readPtr, 'int', ['int', 'pointer', "int"]);
    var MapsBuffer = Memory.alloc(512);
    var MapsFile = new File(FakeMaps, "w");
    Interceptor.replace(openPtr, new NativeCallback(function(pathname, flag) {
        var FD = open(pathname, flag);
        var ch = pathname.readCString();
        if (ch.indexOf("/proc/") >= 0 && ch.indexOf("maps") >= 0) {
            console.log("open : ", pathname.readCString());
            while (parseInt(read(FD, MapsBuffer, 512)) !== 0) {
                var MBuffer = MapsBuffer.readCString();
                MBuffer = MBuffer.replaceAll("/data/local/tmp/re.frida.server/frida-agent-64.so", "FakingMaps");
                MBuffer = MBuffer.replaceAll("re.frida.server", "FakingMaps");
                MBuffer = MBuffer.replaceAll("frida-agent-64.so", "FakingMaps");
                MBuffer = MBuffer.replaceAll("frida-agent-32.so", "FakingMaps");
                MBuffer = MBuffer.replaceAll("frida", "FakingMaps");
                MBuffer = MBuffer.replaceAll("/data/local/tmp", "/data");
                MapsFile.write(MBuffer);
            }
            var filename = Memory.allocUtf8String(FakeMaps);
            return open(filename, flag);
        }
        return FD;
    }, 'int', ['pointer', 'int']));
}

function getPreAndPost() {
    let bytes_count = 8; // 读取前8个字节
    let address = Module.getExportByName("libc.so", "open");

    // 获取原始函数地址
    let before = ptr(address);
    console.log("");
    console.log("Before hook: ");
    console.log(hexdump(before, {
        offset: 0,
        length: bytes_count,
        header: true,
        ansi: true
    }));

    // Hook 目标函数
    Interceptor.attach(address, {
        onEnter: function(args) {
            console.log("after the function (hooked):");

            // 获取 hook 后的机器码
            let after = ptr(address);
            console.log(hexdump(after, {
                offset: 0,
                length: bytes_count,
                header: true,
                ansi: true
            }));
        },
        onLeave: function(retval) {
            // 可以在这里对返回值进行处理（如果需要）
        }
    });
}

function hook_memcmp_addr(){
    let memcmp_addr = Module.getExportByName("libc.so", "memcmp"); // memcmp 的地址
    let base_addr = Module.findBaseAddress("lib52pojie.so"); // 目标库的基地址

    if (base_addr) {
        let target_function_addr = base_addr.add(0x013974); // 偏移地址计算实际地址

        Interceptor.attach(memcmp_addr, {
            onEnter: function(args) {
                // 检查调用栈的返回地址是否为目标函数地址
                if (this.context.lr.equals(target_function_addr)) {
                    console.log("memcmp called from target function at: " + target_function_addr);
                    this.shouldModify = true;
                } else {
                    this.shouldModify = false;
                }
            },
            onLeave: function(retval) {
                if (this.shouldModify) {
                    retval.replace(1); // 强制修改返回值为 1
                    console.log("Modified memcmp result to 1.");
                }
            }
        });
    } else {
        console.log("Failed to find base address for libnative.so.");
    }
}

function hook_svc(){
    let target_code_hex;
    let call_number_openat;  //系统调用号
    let arch = Process.arch;    //目标进程的架构

    if (arch === "arm"){
        target_code_hex = "00 00 00 EF";  //svc 0
        call_number_openat = 322;
    }else if (arch === "arm64")
    {
        target_code_hex = " 01 00 00 D4";
        call_number_openat = 56;
    }else{
        console.log("unsupport this arch");
    }

    if (arch){
        console.log("\nthe_arch = " + arch);  
        // 枚举进程的内存范围，寻找只读内存段
        Process.enumerateRanges('r--').forEach(function (range) {
            if(!range.file || !range.file.path){  // 如果内存段没有文件路径，跳过
                return;
            }
            let path = range.file.path;  
            if ((!path.startsWith("/data/app/")) || (!path.endsWith(".so"))){
                return;
            }
            let baseAddress = Module.getBaseAddress(path); 
            let soNameList = path.split("/");  
            let soName = soNameList[soNameList.length - 1];  
            console.log("\npath = " + path + " , baseAddress = " + baseAddress + 
                        " , rangeAddress = " + range.base + " , size = " + range.size);

            Memory.scan(range.base, range.size, target_code_hex, {
                onMatch: function (match){
                    let code_address = match;  // 获取匹配到的指令地址
                    let code_address_str = code_address.toString();  // 转换为字符串
                    // 如果地址的最低位是0, 4, 8, c中的任意一个，说明可能是svc指令  四字节对齐00结尾
                    if (code_address_str.endsWith("0") || code_address_str.endsWith("4") || 
                        code_address_str.endsWith("8") || code_address_str.endsWith("c")){
                        console.log("--------------------------");
                        let call_number = 0;  // 初始化系统调用号
                        if ("arm" === arch){
                            // 获取svc指令后面的立即数，作为系统调用号
                            call_number = (code_address.sub(0x4).readS32()) & 0xFFF;
                        }else if("arm64" === arch){
                            call_number = (code_address.sub(0x4).readS32() >> 5) & 0xFFFF;
                        }else {
                            console.log("the arch get call_number not support!"); 
                        }
                        console.log("find svc : so_name = " + soName + " , address = " + code_address + 
                                    " , call_number = " + call_number + " , offset = " + code_address.sub(baseAddress));
                        if (call_number_openat === call_number){
                            let target_hook_addr = code_address;
                            let target_hook_addr_offset = target_hook_addr.sub(baseAddress);
                            console.log("find svc openat , start inlinehook by frida!");
                            Interceptor.attach(target_hook_addr, {
                                onEnter: function (args){  // 当进入挂钩函数时
                                    console.log("\nonEnter_" + target_hook_addr_offset + " , __NR_openat , args[1] = " + 
                                                  args[1].readCString());
                                    // 修改openat的第一个参数为指定路径
                                    this.new_addr = Memory.allocUtf8String("/data/user/0/com.zj.wuaipojie/maps");
                                    args[1] = this.new_addr;
                                    console.log("onEnter_" + target_hook_addr_offset + " , __NR_openat , args[1] = " + 
                                                  args[1].readCString());
                                }, 
                                onLeave: function (retval){  // 当离开挂钩函数时
                                    console.log("onLeave_" + target_hook_addr_offset + " , __NR_openat , retval = " + retval)
                                }
                            });
                        }
                    }
                }, 
                onComplete: function () {}  // 搜索完成后的回调函数
            });
        });
    }
}

function anti_str(){
    let strstr_addr = Module.getExportByName("lib52pojie.so", "_Z13anti_str_mapsv"); // memcmp 的地址
    Interceptor.attach(strstr_addr, {
        onEnter: function(args) {

        },
        onLeave: function(retval) {
            retval.replace(0); 
        }
    });
}

function test(){
    Java.perform(function () {
        // 获取 AESUtils 类
        var AESUtils = Java.use("com.zj.wuaipojie.util.AESUtils");
    
        // Hook aes 方法
        AESUtils.aes.implementation = function (arg) {
            var originalReturn = this.aes(arg);
            var modifiedReturn = "admin";
            return modifiedReturn;
        };
    });
    
}

setImmediate(test);
