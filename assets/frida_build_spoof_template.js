/*
 * spoof_tablet.js —— 把 Android 手机伪装成"平板"，用于多设备同时登录实验
 *
 * 依据（静态逆向）：
 *   DeviceStatusModel.DeviceType: 0 default / 1 web / 2 android / 3 ios / 4 mac / 5 win / 6 iPad / 7 APAD
 *   业务代码读机型走的是 SG 影子类 com.alibaba.wireless.security.aopsdk.replace.android.os.Build
 *   （只有 getMODEL / getRELEASE / getSERIAL 三个方法），所以影子类必须一起 hook。
 *
 * 用法（需 root + frida-server；目标必须是**官方签名**的 APK）：
 *   frida -U -f com.alibaba.android.rimet.w2534344268 -l spoof_tablet.js --no-pause
 *   或先 `frida -U -f ... --no-pause` 再 `%load spoof_tablet.js`
 *
 * 额外建议（不改代码就能影响"是否平板"判定）：
 *   adb shell wm size 1600x2560
 *   adb shell wm density 320        # smallestWidth ≈ 800dp，进入平板布局
 *   恢复：adb shell wm size reset; adb shell wm density reset
 */

'use strict';

var FAKE = {
    MODEL: 'SM-X910',          // Galaxy Tab S9
    MANUFACTURER: 'samsung',
    BRAND: 'samsung',
    DEVICE: 'gts9wifi',
    PRODUCT: 'gts9wifi',
    HARDWARE: 'qcom'
};

Java.perform(function () {
    // 1) SG 影子 Build：钉钉业务层实际调用的入口
    try {
        var ShadowBuild = Java.use('com.alibaba.wireless.security.aopsdk.replace.android.os.Build');
        ShadowBuild.getMODEL.implementation = function () {
            return FAKE.MODEL;
        };
        console.log('[+] shadow Build.getMODEL() -> ' + FAKE.MODEL);
    } catch (e) {
        console.log('[-] shadow Build hook failed: ' + e);
    }

    // 2) 真实 android.os.Build 静态字段：native / SDK / UA 直接读这里
    Object.keys(FAKE).forEach(function (field) {
        try {
            Java.use('android.os.Build')[field].value = FAKE[field];
            console.log('[+] Build.' + field + ' -> ' + FAKE[field]);
        } catch (e) {
            console.log('[-] Build.' + field + ' write failed: ' + e);
        }
    });

    // 3) WebView UA 去掉 "Mobile"：很多"是否平板"判断看 UA
    try {
        var WebSettings = Java.use('android.webkit.WebSettings');
        var origUA = WebSettings.getUserAgentString;
        WebSettings.getUserAgentString.implementation = function () {
            var ua = origUA.call(this);
            return ua.replace('Mobile ', '');
        };
        console.log('[+] WebSettings.getUserAgentString() 已去掉 Mobile');
    } catch (e) {
        console.log('[-] UA hook failed: ' + e);
    }

    // 4) 打印确认
    setTimeout(function () {
        Java.perform(function () {
            try {
                console.log('[i] Build.MODEL now = ' + Java.use('android.os.Build').MODEL.value);
            } catch (e) {}
        });
    }, 1500);
});
