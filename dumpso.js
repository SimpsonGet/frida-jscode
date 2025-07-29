function hook_dlopen(soName){
    var soName = "libGameVMP.so"
    Interceptor.attach(Module.findExportByName(null, 'android_dlopen_ext'),{
        onEnter : function(args){
            //arg[0] 是要加载的so的路径
            if(args[0] != null){
                let loadPath = Memory.readUtf8String(args[0])
                console.log("dlopen call is: " + loadPath + "\n")
                if (loadPath.includes(soName)){
                    this.flag = 1
                }
            }
        },onLeave:function(retval){
            console.log("dlopen return\n")
            if (this.flag === 1){
                dumpSo(soName)
                this.flag = 0
            }
        }
    })
}

function dumpSo(filename){
    var handle = Process.getModuleByName(filename)
    console.log("[dump] start dumping ---------" + handle)
    var path = "/data/data/com.shizhuang.duapp/" + handle.name + "_" + handle.base + "_" + ptr(handle.size) + ".so"
    var file_handle = new File(path, "wb")
    if(!file_handle){
        console.log("[dump] dump failed")
        return
    }
    Memory.protect(ptr(handle.base), handle.size, 'rwx')
    var libbuffer = ptr(handle.base).readByteArray(handle.size)
    file_handle.write(libbuffer)
    file_handle.close()
    console.log("[dump] dump finished and path is: " + path)
}
setImmediate(hook_dlopen("libxxx.so"))