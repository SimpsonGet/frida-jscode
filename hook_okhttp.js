// ✅ 功能总览：
// 功能项	说明
// ✅ Hook OkHttp 的同步 & 异步请求（execute / enqueue）	
// ✅ 抓取 URL、Method、Headers	
// ✅ 抓取 POST 请求体（request body）	
// ✅ 抓取服务器响应体（response body）	
// ✅ 打印调用堆栈（可选开关）	
// ✅ 使用 Okio 的 buffer 处理 request/response	

Java.perform(function () {
    const RealCall = Java.use('okhttp3.RealCall');
    const Buffer = Java.use('okio.Buffer');
    const Interceptor = Java.use('okhttp3.Interceptor');
    const ResponseBody = Java.use('okhttp3.ResponseBody');
    const Charset = Java.use('java.nio.charset.Charset');
    const StandardCharsets = Java.use('java.nio.charset.StandardCharsets');
    const Exception = Java.use('java.lang.Exception');

    const UTF8 = StandardCharsets.UTF_8.value;

    // 是否启用堆栈打印（调试时用）
    const ENABLE_STACK = false;

    // --- Hook execute()
    RealCall.execute.implementation = function () {
        const request = this.request();
        logRequest(request, "execute()");
        return this.execute();
    };

    // --- Hook enqueue()
    RealCall.enqueue.implementation = function (callback) {
        const request = this.request();
        logRequest(request, "enqueue()");
        return this.enqueue(callback);
    };

    // --- Hook Interceptor，抓 response
    const InterceptorClass = Java.use('okhttp3.internal.http.RealInterceptorChain');

    InterceptorClass.proceed.overload('okhttp3.Request').implementation = function (request) {
    const response = this.proceed(request);

    try {
        const responseBody = response.body();
        if (responseBody != null) {
        const contentLength = responseBody.contentLength();
        const contentType = responseBody.contentType();
        const source = responseBody.source();
        source.request(java.lang.Long.MAX_VALUE); // 读取所有内容
        const buffer = source.buffer();
        const clone = buffer.clone(); // 防止原始 buffer 被清空
        const bodyStr = clone.readString(contentType ? contentType.charset(UTF8) : UTF8);

        console.log("=== [OkHttp Response Intercepted] ===");
        console.log("URL: " + request.url().toString());
        console.log("Response Body:\n" + bodyStr);
        console.log("======================================");
        }
    } catch (err) {
        console.error("[!] Exception in response interceptor: " + err);
    }

    return response;
    };

    // ---- 通用日志函数 ----
    function logRequest(request, source) {
    try {
        const method = request.method();
        const url = request.url().toString();
        const headers = request.headers();
        let body = "";

        const requestBody = request.body();
        if (requestBody) {
        const buffer = Buffer.$new();
        requestBody.writeTo(buffer);
        body = buffer.readUtf8();
        }

        console.log("=== [OkHttp Request - " + source + "] ===");
        console.log("Method: " + method);
        console.log("URL: " + url);
        console.log("Headers: " + headers.toString());
        if (body.length > 0) {
        console.log("Body:\n" + body);
        }

        if (ENABLE_STACK) {
        console.log("Stack:\n" + Exception.$new().getStackTrace().join("\n"));
        }

        console.log("=======================================");
    } catch (err) {
        console.error("[!] Exception in logRequest: " + err);
    }
    }
});
