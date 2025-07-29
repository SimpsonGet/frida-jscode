function hook_dlopen() {
    Interceptor.attach(Module.findExportByName(null, "android_dlopen_ext"),
        {
            onEnter: function (args) {
                this.fileName = args[0].readCString()
                console.log(`dlopen onEnter: ${this.fileName}`)
                if (this.fileName !== undefined && this.fileName.indexOf("libmsaoaidsec.so") >= 0) {
                    hook_call_constructors()
                }
            }, onLeave: function(retval){
                console.log(`dlopen onLeave fileName: ${this.fileName}`)
                if(this.fileName != null && this.fileName.indexOf("libmsaoaidsec.so") >= 0){
                    let JNI_OnLoad = Module.getExportByName(this.fileName, 'JNI_OnLoad')
                    console.log(`dlopen onLeave JNI_OnLoad: ${JNI_OnLoad}`)
                }
            }
        }
    );
}

function hook_call_constructors(){
    var arc = Process.arch
    if (arc.includes("64")){
        //0x2091c 
        let linker64_base_addr = Module.findBaseAddress("linker64")
        let offset = 0x2091c  //64位

        let call_constructors_addr = linker64_base_addr.add(offset)
        var lister = Interceptor.attach(call_constructors_addr,{
            onEnter: function(args){
                // console.log("hook in constructors_addr onEnter")
                var sublib = Process.findModuleByName("libmsaoaidsec.so")
                // hook_pthred_create()

                if (sublib != null){
                    hook_sub(sublib, 0x1b8d4, false)
                    hook_sub(sublib, 0x1B924, false)
                    lister.detach()
                }
            }
        })
    }
    else{
        let linker_base_addr = Module.findBaseAddress("linker")
        let offset = 13315      //32位

        let call_constructors_addr = linker_base_addr.add(offset)
        var lister = Interceptor.attach(call_constructors_addr,{
            onEnter: function(args){
                var sublib = Process.findModuleByName("libmsaoaidsec.so")
                // hook_pthred_create()

                if (sublib != null){
                    // hook_sub(sublib,, true)
                    // hook_sub(sublib,, true)
                    // hook_sub(sublib,0x19c09)
                    lister.detach()
                }
            }
        })
    }
}
function hook_pthred_create(){
    console.log("libmsaoaidsec.so --- " + Process.findModuleByName("libmsaoaidsec.so").base)
    Interceptor.attach(Module.findExportByName('libc.so','pthread_create'),{
        onEnter(args){
            let func_addr = args[2]
            console.log(`The thread Called function address is: ${func_addr}`)
            var offset = func_addr.sub(Process.findModuleByName("libmsaoaidsec.so").base)
            console.log("offset "+ offset)
        }
    })
}

//libmsaoaidsec.so --- 0x7956608000
//0x7956624544    0x79566238d4      0x795662ee5c
//0x1b8d4   0x1c544     0x26e5c

function hook_sub(sublib, offset, flag){
    if(flag){
        var addr = sublib.base.add(offset).or(1)
    }else{
        var addr = sublib.base.add(offset)
    }
    Interceptor.replace(addr, new NativeCallback(function () {
        console.log(`hook_sub ${offset} >>>>>>>>>>>>>>>>> replace`)
      }, 'void', []));
}