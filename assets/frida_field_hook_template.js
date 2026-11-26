/*
 * 钉钉 8.2.2.1 专属版（com.alibaba.android.rimet.w2534344268）解锁脚本
 *
 * 适用：已 root / 已注入 frida-gadget / 可 attach 的实例。
 * 用法：frida -U -f com.alibaba.android.rimet.w2534344268 -l unlock.js --no-pause
 *      或 frida -U -n <进程名> -l unlock.js
 *
 * 解锁内容：
 *   1) defpackage.ywm.a()  -> true        「设置 → 开发者选项」入口可见 + DeveloperOptionsActivity 可进
 *   2) Doraemon.getRunningMode() -> 1     DevSettingActivity 门控通过（环境切换 / endpoint 覆盖 / WebView 调试开关全部解锁）
 *   3) WebView.setWebContentsDebuggingEnabled(true)  全局强制开启（chrome://inspect 可连）
 *   4) 顺带打印 DevSetting 门控相关的几个关键判断，便于确认
 *
 * 注意：类名 `ywm` 在默认包（dex 描述符 Lywm;），Frida 里写 'ywm'。
 */
Java.perform(function () {
    var TAG = '[unlock] ';
    var ok = 0;

    function log(s) { console.log(TAG + s); }

    // ---------- 1) ywm.a() ----------
    try {
        var ywm = Java.use('ywm');
        ywm.a.overload().implementation = function () {
            return true;
        };
        try { ywm.f69400a.value = true; } catch (e1) { /* 字段名在不同构建里可能被重命名 */ }
        log('ywm.a() -> true  ✔');
        ok++;
    } catch (e) {
        log('ywm hook failed: ' + e);
    }

    // ---------- 2) Doraemon running mode ----------
    try {
        var Doraemon = Java.use('com.alibaba.doraemon.Doraemon');
        Doraemon.getRunningMode.overload().implementation = function () {
            return 1;   // MODE_DEBUG
        };
        try { Doraemon.sMode.value = 1; } catch (e2) { log('sMode 直接写失败（继续用 hook）: ' + e2); }
        log('Doraemon.getRunningMode() -> 1  ✔');
        ok++;
    } catch (e) {
        log('Doraemon hook failed: ' + e);
    }

    // ---------- 3) WebView 远程调试 ----------
    try {
        var WebView = Java.use('android.webkit.WebView');
        var m = WebView.setWebContentsDebuggingEnabled.overload('boolean');
        m.implementation = function (b) {
            // .call 走原实现，避免递归
            return m.call(WebView, true);
        };
        log('WebView.setWebContentsDebuggingEnabled(true) 强制开启 ✔');
        ok++;
    } catch (e) {
        log('WebView hook failed: ' + e);
    }

    // ---------- 4) 观察点：DevSetting 门控依赖 ----------
    try {
        var Dev = Java.use('com.alibaba.android.user.devset.DevSettingActivity');
        log('DevSettingActivity found, static v1=' + Dev.v1.value);
    } catch (e) { /* 未加载时忽略 */ }

    log('done, ' + ok + '/3 项已挂钩。进入「设置 → 关于」长按版本号 或 直接打开 DevSettingActivity 验证。');
});

/*
 * 可选：如果你已经有一个 Surgeon patch dex（见 tools/surgeon/），可用下面几行在运行时加载它，
 * 这样无需 hook 具体方法，而是走钉钉官方的热修通道替换任意 instrumented 方法：
 *
 * Java.perform(function () {
 *   var ctx = Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
 *   var PatchInfo = Java.use('com.android.alibaba.ip.common.PatchInfo');
 *   var info = PatchInfo.$new();
 *   info.baseVersion.value = '8.2.2.1';
 *   info.patchVersion.value = 1;
 *   info.priority.value = 1;
 *   var p = Java.use('com.android.alibaba.ip.server.InstantPatcher').create(ctx);
 *   var r = p.handlePatches('/data/local/tmp/surgeon1.dex', info);
 *   console.log('patch resCode=' + r.resCode.value);
 * });
 */
