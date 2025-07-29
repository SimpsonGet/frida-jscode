// ========== 工具函数 ==========

// 安全获取模块信息，失败返回 null
function safeGetModuleByAddress(address) {
    try {
        let module = Process.getModuleByAddress(address);
        if (module) {
            return module;
        }
    } catch (e) {
        // 获取失败，返回 null
    }
    return null;
}

// 安全读取 UTF-16 字符串，失败返回 null
function safeReadUtf16String(ptr, len) {
    try {
        return Memory.readUtf16String(ptr, len);
    } catch (e) {
        console.warn(`❌ Failed to read UTF-16 string at ${ptr}: ${e.message}`);
        return null;
    }
}

// 获取当前线程的调用栈（Backtrace），带符号信息
function getBacktrace(context) {
    const trace = Thread.backtrace(context, Backtracer.ACCURATE)
        .map(address => {
            const symbol = DebugSymbol.fromAddress(address);
            if (symbol && symbol.name) {
                return `${address} ${symbol.moduleName}!${symbol.name}!+0x${symbol.address.sub(Module.findBaseAddress(symbol.moduleName)).toString(16)}`;
            } else {
                const module = safeGetModuleByAddress(address);
                if (module) {
                    const offset = ptr(address).sub(module.base);
                    return `${address} ${module.name} + 0x${offset.toString(16)}`;
                } else {
                    return `${address} [Unknown]`;
                }
            }
        }).join("\n");
    return `🔍 Backtrace:\n${trace}\n`;
}

// ========== Hook JNI 方法 ==========

// Hook GetStringUTFChars
function hookGetStringUTFChars(targetStr = null, backtrace = false) {
    const symbols = Module.enumerateSymbolsSync("libart.so");
    for (let sym of symbols) {
        if (!sym.name.includes("CheckJNI") && sym.name.includes("GetStringUTFChars")) {
            console.log("[*] Found GetStringUTFChars at: " + sym.address + " (" + sym.name + ")");
            Interceptor.attach(sym.address, {
                onEnter: function (args) {
                    this.jstr = args[1];     // jstring 对象
                    this.isCopy = args[2];   // 是否是拷贝
                },
                onLeave: function (retval) {
                    if (retval.isNull()) return;
                    const cstr = Memory.readUtf8String(retval);
                    const shouldLog = targetStr === null || cstr.includes(targetStr);
                    if (!shouldLog) return;

                    let log = "\n====== 🧪 GetStringUTFChars Hook ======\n";
                    log += `📥 jstring: ${this.jstr}\n`;
                    log += `📥 isCopy: ${this.isCopy}\n`;
                    log += `📤 C String: ${cstr}\n`;
                    if (backtrace) log += getBacktrace(this.context);
                    log += "====== ✅ Hook End ======\n";
                    console.log(log);
                }
            });
            break;
        }
    }
}

// Hook NewStringUTF
function hookNewStringUTF(targetStr = null, backtrace = false) {
    const symbols = Module.enumerateSymbolsSync("libart.so");
    for (let sym of symbols) {
        if (!sym.name.includes("CheckJNI") && sym.name.includes("NewStringUTF")) {
            console.log("[*] Found NewStringUTF at: " + sym.address + " (" + sym.name + ")");
            Interceptor.attach(sym.address, {
                onEnter: function (args) {
                    this.cstr = args[1]; // 传入的 C 字符串指针
                    let log = "\n====== 🧪 NewStringUTF Hook ======\n";
                    try {
                        const inputStr = Memory.readUtf8String(this.cstr);
                        this.shouldLog = (inputStr !== null) && (targetStr === null || inputStr.includes(targetStr));
                        if (!this.shouldLog) return;
                        log += `📥 Input C String: ${inputStr}\n`;
                        if (backtrace) log += getBacktrace(this.context);
                        this._log = log;
                    } catch (e) {
                        console.error("Error reading string or generating log:", e);
                    }
                },
                onLeave: function (retval) {
                    if (this.shouldLog) {
                        this._log += `📤 Returned Java String: ${retval}\n`;
                        this._log += "====== ✅ Hook End ======\n";
                        console.log(this._log);
                    }
                }
            });
            break;
        }
    }
}

// Hook NewString（UTF-16）
function hookNewString(targetStr = null, backtrace = false) {
    const symbols = Module.enumerateSymbolsSync("libart.so");
    for (let sym of symbols) {
        if (!sym.name.includes("CheckJNI") && sym.name.includes("NewString")) {
            console.log("[*] Found NewString at: " + sym.address + " (" + sym.name + ")");
            Interceptor.attach(sym.address, {
                onEnter: function (args) {
                    this.len = args[2].toInt32(); // 字符串长度
                    const str = safeReadUtf16String(args[1], this.len); // 读取 UTF-16 内容
                    this.shouldLog = targetStr === null || (str != null && str.includes(targetStr));
                    if (!this.shouldLog) return;
                    this._log = "\n====== 🧪 NewString Hook ======\n";
                    this._log += `📥 Length: ${this.len}\n`;
                    this._log += str !== null ?
                        `📥 UTF-16 Content: ${str}\n` :
                        `📥 UTF-16 Content: [invalid UTF-16, ptr=${args[1]}]\n`;
                    if (backtrace) this._log += getBacktrace(this.context);
                },
                onLeave: function (retval) {
                    if (this.shouldLog) {
                        this._log += `📤 Returned jstring: ${retval}\n`;
                        this._log += "====== ✅ Hook End ======\n";
                        console.log(this._log);
                    }
                }
            });
            break;
        }
    }
}

// Hook GetStringChars（返回 UTF-16 内容）
function hookGetStringChars(targetStr = null, backtrace = false) {
    const symbols = Module.enumerateSymbolsSync("libart.so");
    for (let sym of symbols) {
        if (!sym.name.includes("CheckJNI") && sym.name.includes("GetStringChars")) {
            console.log("[*] Found GetStringChars at: " + sym.address + " (" + sym.name + ")");
            Interceptor.attach(sym.address, {
                onEnter: function (args) {
                    this.jstr = args[1];
                    this.isCopy = args[2];
                },
                onLeave: function (retval) {
                    if (retval.isNull()) return;
                    const str = safeReadUtf16String(retval, 100); // 读取最多 100 个字符
                    const shouldLog = targetStr === null || (str != null && str.includes(targetStr));
                    if (!shouldLog) return;

                    let log = "\n====== 🧪 GetStringChars Hook ======\n";
                    log += `📥 jstring: ${this.jstr}\n`;
                    log += `📥 isCopy: ${this.isCopy}\n`;
                    log += `📤 UTF-16 String: ${str}\n`;
                    if (backtrace) log += getBacktrace(this.context);
                    log += "====== ✅ Hook End ======\n";
                    console.log(log);
                }
            });
            break;
        }
    }
}

// Hook ReleaseStringChars
function hookReleaseStringChars(backtrace = false) {
    const symbols = Module.enumerateSymbolsSync("libart.so");
    for (let sym of symbols) {
        if (!sym.name.includes("CheckJNI") && sym.name.includes("ReleaseStringChars")) {
            console.log("[*] Found ReleaseStringChars at: " + sym.address + " (" + sym.name + ")");
            Interceptor.attach(sym.address, {
                onEnter: function (args) {
                    let log = "\n====== 🧪 ReleaseStringChars Hook ======\n";
                    log += `📥 jstring: ${args[1]}\n`;
                    log += `📥 chars: ${args[2]}\n`;
                    if (backtrace) log += getBacktrace(this.context);
                    log += "====== ✅ Hook End ======\n";
                    console.log(log);
                }
            });
            break;
        }
    }
}

// Hook GetStringLength（返回 UTF-16 字符长度）
function hookGetStringLength(backtrace = false) {
    const symbols = Module.enumerateSymbolsSync("libart.so");
    for (let sym of symbols) {
        if (!sym.name.includes("CheckJNI") && sym.name.includes("GetStringLength")) {
            console.log("[*] Found GetStringLength at: " + sym.address + " (" + sym.name + ")");
            Interceptor.attach(sym.address, {
                onEnter: function (args) {
                    this.jstr = args[1];
                    this._log = "\n====== 🧪 GetStringLength Hook ======\n";
                    this._log += `📥 jstring: ${this.jstr}\n`;
                    if (backtrace) this._log += getBacktrace(this.context);
                },
                onLeave: function (retval) {
                    this._log += `📤 Length: ${retval.toInt32()}\n`;
                    this._log += "====== ✅ Hook End ======\n";
                    console.log(this._log);
                }
            });
            break;
        }
    }
}

// Hook GetStringUTFLength（返回 UTF-8 编码后的长度）
function hookGetStringUTFLength(backtrace = false) {
    const symbols = Module.enumerateSymbolsSync("libart.so");
    for (let sym of symbols) {
        if (!sym.name.includes("CheckJNI") && sym.name.includes("GetStringUTFLength")) {
            console.log("[*] Found GetStringUTFLength at: " + sym.address + " (" + sym.name + ")");
            Interceptor.attach(sym.address, {
                onEnter: function (args) {
                    this.jstr = args[1];
                    this._log = "\n====== 🧪 GetStringUTFLength Hook ======\n";
                    this._log += `📥 jstring: ${this.jstr}\n`;
                    if (backtrace) this._log += getBacktrace(this.context);
                },
                onLeave: function (retval) {
                    this._log += `📤 UTF-8 length: ${retval.toInt32()}\n`;
                    this._log += "====== ✅ Hook End ======\n";
                    console.log(this._log);
                }
            });
            break;
        }
    }
}

// ========== 启动 Hook ==========

setImmediate(function () {
    // 设置目标字符串和是否打印回溯
    let targetStr = "knGGXR0bR7LQn4eRCvJsdZ4D96wrRcYi2zPWWxLMOs2QMQNk";
    let backtrace = true;

    // 启动 Hook，按需启用
    hookNewStringUTF(targetStr, backtrace);
    hookGetStringUTFChars(targetStr, backtrace);
    hookNewString(targetStr, backtrace);
    hookGetStringChars(targetStr, backtrace);
    // hookGetStringUTFLength(true);
    // hookGetStringLength(true);
    // hookReleaseStringChars(true);
});