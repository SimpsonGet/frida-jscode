function printStackTrace() {
    var Exception = Java.use("java.lang.Exception");
    var stackTrace = Exception.$new().getStackTrace();
    var i;

    console.log("\n====== Call Stack ======");
    for (i = 0; i < stackTrace.length; i++) {
        console.log(stackTrace[i].toString());
    }
    console.log("========================\n");
}

//console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new()))