function getArtprt(obj){
    var handle = null;
    try{
        handle = obj.$handle;
    }catch(e){
    }
    if(handle == null){
        try{
            handle = obj.$h;
        }catch(e){
        }
    }
    if (handle == null){
        try{
            handle = obj.handle;
        }catch(e){
        }
    }
    return handle;
}

function findso(classpath){
    Java.perform(function(){
        var MethodClass = Java.use(classpath);
        var methodobj = MethodClass.intercept.overload('okhttp3.Interceptor$Chain', 'long');  //具体的jni方法
        var methodaddr = ptr(getArtprt(methodobj).add(32).readPointer());  //查看手机的偏移为4x8

        var libInfo = JSON.parse(JSON.stringify(Process.findModuleByAddress(methodaddr)));
        var baseAddress = libInfo.base;
        var modulename = libInfo.name;
        console.log("address : ",methodaddr , "offset: ", methodaddr.sub(baseAddress) ," module : ", modulename);
    })
}

function main(){
    findso("com.xingin.shield.http.XhsHttpInterceptor")
}